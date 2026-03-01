#!/usr/bin/env python3
"""
Materialize Obsidian vault files from a CouchDB LiveSync database.
Supports E2EE (HKDF/V2) encrypted vaults.

Modes:
  - Initial: full materialization of all files
  - Watch: listen to CouchDB _changes feed, update files on change (1s debounce)

Environment variables:
    COUCHDB_URL       - CouchDB URL (default: http://localhost:5984)
    COUCHDB_DATABASE  - Database name (default: obsidiandb)
    COUCHDB_USER      - CouchDB username
    COUCHDB_PASSWORD  - CouchDB password
    E2EE_PASSPHRASE   - E2EE passphrase (required if vault is encrypted)
    PBKDF2_SALT       - Base64-encoded PBKDF2 salt (required if vault is encrypted)
    OUTPUT_DIR        - Output directory (default: /output)
    DEBOUNCE          - Debounce interval in seconds (default: 1)
"""

import base64
import json
import logging
import os
import sys
import threading
import time
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from urllib.parse import urlparse, quote
from urllib.request import Request, urlopen

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("materialize")

# --- Encryption ---

IV_LENGTH = 12
HKDF_SALT_LENGTH = 32
PBKDF2_ITERATIONS = 310_000


def make_decryptor(passphrase: str, pbkdf2_salt: bytes):
    """Create a decryptor function with cached master key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    log.info("Deriving master key (PBKDF2, %d iterations)...", PBKDF2_ITERATIONS)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=pbkdf2_salt,
        iterations=PBKDF2_ITERATIONS,
    )
    master_key_raw = kdf.derive(passphrase.encode("utf-8"))
    log.info("Master key derived.")

    def decrypt_chunk(encrypted_data: str) -> str:
        if not encrypted_data.startswith("%="):
            raise ValueError(f"Unknown encryption prefix: {encrypted_data[:10]}")
        raw = base64.b64decode(encrypted_data[2:])
        if len(raw) < IV_LENGTH + HKDF_SALT_LENGTH:
            raise ValueError(f"Encrypted data too short: {len(raw)} bytes")
        iv = raw[:IV_LENGTH]
        hkdf_salt = raw[IV_LENGTH : IV_LENGTH + HKDF_SALT_LENGTH]
        ciphertext = raw[IV_LENGTH + HKDF_SALT_LENGTH :]
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=hkdf_salt, info=b"")
        chunk_key = hkdf.derive(master_key_raw)
        aesgcm = AESGCM(chunk_key)
        return aesgcm.decrypt(iv, ciphertext, None).decode("utf-8")

    return decrypt_chunk


# --- CouchDB client ---


class CouchDB:
    def __init__(self, url: str, database: str, user: str, password: str):
        self.url = url.rstrip("/")
        self.database = database
        self.base = f"{self.url}/{database}"
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()

    def _request(self, path: str, method: str = "GET", body: bytes = None) -> dict:
        url = f"{self.base}{path}"
        req = Request(url, data=body, method=method)
        req.add_header("Authorization", f"Basic {self.auth}")
        req.add_header("Accept", "application/json")
        if body:
            req.add_header("Content-Type", "application/json")
        with urlopen(req) as resp:
            return json.loads(resp.read())

    def get_all_docs(self) -> list[dict]:
        return self._request("/_all_docs?include_docs=true")["rows"]

    def get_doc(self, doc_id: str) -> dict:
        return self._request(f"/{quote(doc_id, safe='')}")

    def get_docs_bulk(self, doc_ids: list[str]) -> list[dict]:
        data = self._request(
            "/_all_docs?include_docs=true",
            method="POST",
            body=json.dumps({"keys": doc_ids}).encode(),
        )
        return [row["doc"] for row in data["rows"] if "doc" in row]

    def changes_stream(self, since: str = "now", heartbeat: int = 10000):
        """Yield change dicts from a continuous _changes feed."""
        parsed = urlparse(self.base)
        path = f"{parsed.path}/_changes?feed=continuous&since={since}&heartbeat={heartbeat}"

        while True:
            try:
                if parsed.scheme == "https":
                    conn = HTTPSConnection(parsed.hostname, parsed.port or 443)
                else:
                    conn = HTTPConnection(parsed.hostname, parsed.port or 5984)

                conn.request("GET", path, headers={
                    "Authorization": f"Basic {self.auth}",
                    "Accept": "application/json",
                })
                resp = conn.getresponse()

                buf = b""
                while True:
                    chunk = resp.read(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            change = json.loads(line)
                            if "last_seq" in change:
                                since = change["last_seq"]
                                path = f"{parsed.path}/_changes?feed=continuous&since={since}&heartbeat={heartbeat}"
                            elif "seq" in change:
                                since = change["seq"]
                                path = f"{parsed.path}/_changes?feed=continuous&since={since}&heartbeat={heartbeat}"
                                yield change
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                log.warning("Changes feed disconnected: %s. Reconnecting in 5s...", e)
                time.sleep(5)


# --- Materializer ---


class Materializer:
    def __init__(self, db: CouchDB, output_dir: Path, decrypt_fn=None):
        self.db = db
        self.output_dir = output_dir
        self.decrypt_fn = decrypt_fn
        # In-memory index: doc_id -> metadata doc
        self.file_index: dict[str, dict] = {}

    def write_file(self, meta: dict) -> bool:
        """Materialize a single file from its metadata doc. Returns True on success."""
        file_path = meta.get("path", meta["_id"])
        children = meta.get("children", [])
        file_type = meta["type"]

        if not children:
            return True

        try:
            docs = self.db.get_docs_bulk(children)
            chunk_map = {d["_id"]: d for d in docs}

            parts = []
            for chunk_id in children:
                chunk = chunk_map.get(chunk_id)
                if not chunk:
                    log.warning("Missing chunk %s for %s", chunk_id, file_path)
                    continue
                data = chunk["data"]
                if chunk.get("e_") and self.decrypt_fn:
                    data = self.decrypt_fn(data)
                parts.append(data)

            content = "".join(parts)
            out_path = self.output_dir / file_path
            out_path.parent.mkdir(parents=True, exist_ok=True)

            if file_type == "newnote":
                out_path.write_bytes(base64.b64decode(content))
            else:
                out_path.write_text(content, encoding="utf-8")

            mtime = meta.get("mtime")
            if mtime:
                mtime_sec = mtime / 1000.0
                os.utime(out_path, (mtime_sec, mtime_sec))

            return True
        except Exception as e:
            log.error("Failed to materialize %s: %s", file_path, e)
            return False

    def delete_file(self, doc_id: str):
        """Remove a file if it was previously materialized."""
        meta = self.file_index.pop(doc_id, None)
        if not meta:
            return
        file_path = meta.get("path", doc_id)
        out_path = self.output_dir / file_path
        if out_path.exists():
            out_path.unlink()
            log.info("Deleted: %s", file_path)
            # Clean up empty parent dirs
            try:
                parent = out_path.parent
                while parent != self.output_dir:
                    parent.rmdir()  # only removes if empty
                    parent = parent.parent
            except OSError:
                pass

    def full_sync(self) -> str:
        """Full materialization. Returns last update_seq."""
        log.info("Starting full sync...")
        rows = self.db.get_all_docs()
        log.info("Total documents: %d", len(rows))

        metadata = []
        chunks = {}
        for row in rows:
            doc = row.get("doc", {})
            doc_type = doc.get("type")
            if doc_type == "leaf":
                chunks[doc["_id"]] = doc
            elif doc_type in ("plain", "newnote"):
                if not doc.get("_deleted") and not doc.get("deleted"):
                    if doc.get("children"):
                        metadata.append(doc)

        log.info("Active files: %d, chunks: %d", len(metadata), len(chunks))

        written = errors = 0
        for meta in metadata:
            self.file_index[meta["_id"]] = meta
            if self.write_file(meta):
                written += 1
            else:
                errors += 1

        # Clean up files that no longer exist in DB
        existing_paths = {m.get("path", m["_id"]) for m in metadata}
        for path in list(self.output_dir.rglob("*")):
            if path.is_file():
                rel = str(path.relative_to(self.output_dir))
                if rel not in existing_paths:
                    path.unlink()
                    log.info("Cleaned up stale file: %s", rel)

        log.info("Full sync done: %d files, %d errors", written, errors)

        # Get current update_seq
        info = self.db._request("")
        return str(info.get("update_seq", "now"))

    def process_changes(self, changed_ids: set[str]):
        """Process a batch of changed document IDs."""
        if not changed_ids:
            return

        # Fetch the changed docs
        docs = self.db.get_docs_bulk(list(changed_ids))
        doc_map = {d["_id"]: d for d in docs}

        files_to_update = set()

        for doc_id, doc in doc_map.items():
            doc_type = doc.get("type")
            deleted = doc.get("_deleted") or doc.get("deleted")

            if doc_type in ("plain", "newnote"):
                if deleted or not doc.get("children"):
                    self.delete_file(doc_id)
                else:
                    self.file_index[doc_id] = doc
                    files_to_update.add(doc_id)
            elif doc_type == "leaf":
                # A chunk changed — find which files reference it
                for fid, meta in self.file_index.items():
                    if doc_id in meta.get("children", []):
                        files_to_update.add(fid)

        for fid in files_to_update:
            meta = self.file_index.get(fid)
            if meta:
                if self.write_file(meta):
                    log.info("Updated: %s", meta.get("path", fid))
                else:
                    log.error("Failed to update: %s", meta.get("path", fid))


def main():
    url = os.environ.get("COUCHDB_URL", "http://localhost:5984")
    database = os.environ.get("COUCHDB_DATABASE", "obsidiandb")
    user = os.environ.get("COUCHDB_USER", "")
    password = os.environ.get("COUCHDB_PASSWORD", "")
    passphrase = os.environ.get("E2EE_PASSPHRASE", "")
    pbkdf2_salt_b64 = os.environ.get("PBKDF2_SALT", "")
    output_dir = Path(os.environ.get("OUTPUT_DIR", "/output"))
    debounce = float(os.environ.get("DEBOUNCE", "1"))

    if not user or not password:
        log.error("COUCHDB_USER and COUCHDB_PASSWORD are required")
        sys.exit(1)

    db = CouchDB(url, database, user, password)
    output_dir.mkdir(parents=True, exist_ok=True)

    decrypt_fn = None
    if passphrase and pbkdf2_salt_b64:
        pbkdf2_salt = base64.b64decode(pbkdf2_salt_b64)
        decrypt_fn = make_decryptor(passphrase, pbkdf2_salt)

    mat = Materializer(db, output_dir, decrypt_fn)

    # Full sync first
    last_seq = mat.full_sync()
    log.info("Watching for changes (since=%s, debounce=%.1fs)...", last_seq, debounce)

    # Watch _changes with debounce
    pending: set[str] = set()
    lock = threading.Lock()
    last_change_time = 0.0

    def flush_worker():
        """Background thread that flushes pending changes after debounce."""
        nonlocal last_change_time
        while True:
            time.sleep(0.2)
            with lock:
                if not pending:
                    continue
                if time.monotonic() - last_change_time < debounce:
                    continue
                batch = set(pending)
                pending.clear()

            log.info("Processing %d changed docs...", len(batch))
            try:
                mat.process_changes(batch)
            except Exception as e:
                log.error("Error processing changes: %s", e)

    t = threading.Thread(target=flush_worker, daemon=True)
    t.start()

    for change in db.changes_stream(since=last_seq):
        doc_id = change.get("id", "")
        if doc_id.startswith("_design/") or doc_id.startswith("_local/"):
            continue
        with lock:
            pending.add(doc_id)
            last_change_time = time.monotonic()


if __name__ == "__main__":
    main()
