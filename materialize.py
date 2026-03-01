#!/usr/bin/env python3
"""
Materialize Obsidian vault files from a CouchDB LiveSync database.
Supports E2EE (HKDF/V2) encrypted vaults and bidirectional sync.

Modes:
  - Initial: full materialization of all files
  - Watch: listen to CouchDB _changes feed, update files on change (1s debounce)
  - Push: scan filesystem for changes, push to CouchDB

Environment variables:
    COUCHDB_URL       - CouchDB URL (default: http://localhost:5984)
    COUCHDB_DATABASE  - Database name (default: obsidiandb)
    COUCHDB_USER      - CouchDB username
    COUCHDB_PASSWORD  - CouchDB password
    E2EE_PASSPHRASE   - E2EE passphrase (required if vault is encrypted)
    PBKDF2_SALT       - Base64-encoded PBKDF2 salt (required if vault is encrypted)
    OUTPUT_DIR        - Output directory (default: /output)
    DEBOUNCE          - Debounce interval in seconds (default: 1)
    WEBHOOK_URL       - Comma-separated webhook URLs to notify on changes
    WEBHOOK_SECRET    - HMAC-SHA256 secret for signing webhook payloads
    SYNC_MODE         - Global default sync mode: pull, push, or both (default: pull)
    SYNC_RULES        - Comma-separated pattern:mode pairs, e.g. agents/*:push,shared/*:both
    PUSH_INTERVAL     - Filesystem scan interval in seconds (default: 2)
"""

import base64
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import sys
import threading
import time
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse, quote
from urllib.request import Request, urlopen

os.umask(0o002)  # new files: rw-rw-r--, new dirs: rwxrwxr-x

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("materialize")

# --- Encryption ---

IV_LENGTH = 12
HKDF_SALT_LENGTH = 32
PBKDF2_ITERATIONS = 310_000


def derive_master_key(passphrase: str, pbkdf2_salt: bytes) -> bytes:
    """Derive master key from passphrase and salt using PBKDF2."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    log.info("Deriving master key (PBKDF2, %d iterations)...", PBKDF2_ITERATIONS)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=pbkdf2_salt,
        iterations=PBKDF2_ITERATIONS,
    )
    master_key = kdf.derive(passphrase.encode("utf-8"))
    log.info("Master key derived.")
    return master_key


def make_decryptor(master_key: bytes):
    """Create a decryptor function from a pre-derived master key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

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
        chunk_key = hkdf.derive(master_key)
        aesgcm = AESGCM(chunk_key)
        return aesgcm.decrypt(iv, ciphertext, None).decode("utf-8")

    return decrypt_chunk


def make_encryptor(master_key: bytes):
    """Create an encryptor function from a pre-derived master key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    def encrypt_chunk(plaintext: str) -> str:
        iv = os.urandom(IV_LENGTH)
        hkdf_salt = os.urandom(HKDF_SALT_LENGTH)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=hkdf_salt, info=b"")
        chunk_key = hkdf.derive(master_key)
        aesgcm = AESGCM(chunk_key)
        ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
        raw = iv + hkdf_salt + ciphertext
        return "%=" + base64.b64encode(raw).decode("ascii")

    return encrypt_chunk


# --- Sync Rules ---


class SyncRuleEngine:
    """Parses SYNC_MODE + SYNC_RULES, resolves sync mode per path."""

    def __init__(self, default_mode: str, rules_str: str):
        self.default_mode = default_mode
        self.rules: list[tuple[str, str]] = []
        if rules_str:
            for part in rules_str.split(","):
                part = part.strip()
                if ":" in part:
                    pattern, mode = part.rsplit(":", 1)
                    mode = mode.strip().lower()
                    if mode in ("pull", "push", "both"):
                        self.rules.append((pattern.strip(), mode))
                    else:
                        log.warning("Invalid sync mode '%s' in rule '%s', skipping", mode, part)

    def mode_for(self, path: str) -> str:
        for pattern, mode in self.rules:
            if fnmatch.fnmatch(path, pattern):
                return mode
        return self.default_mode

    def should_pull(self, path: str) -> bool:
        return self.mode_for(path) in ("pull", "both")

    def should_push(self, path: str) -> bool:
        return self.mode_for(path) in ("push", "both")

    def has_push_rules(self) -> bool:
        if self.default_mode in ("push", "both"):
            return True
        return any(m in ("push", "both") for _, m in self.rules)

    def has_pull_rules(self) -> bool:
        if self.default_mode in ("pull", "both"):
            return True
        return any(m in ("pull", "both") for _, m in self.rules)


# --- Sync Guard ---


class SyncGuard:
    """Prevents sync loops with time-based cooldown."""

    COOLDOWN = 5.0  # seconds

    def __init__(self):
        self._pulled: dict[str, float] = {}  # path -> monotonic timestamp
        self._pushed: dict[str, float] = {}  # doc_id -> monotonic timestamp
        self._lock = threading.Lock()

    def mark_pulled(self, path: str):
        with self._lock:
            self._pulled[path] = time.monotonic()

    def mark_pushed(self, doc_id: str):
        with self._lock:
            self._pushed[doc_id] = time.monotonic()

    def should_push(self, path: str) -> bool:
        """Return True if this path was NOT recently pulled (safe to push)."""
        with self._lock:
            ts = self._pulled.get(path)
            if ts is None:
                return True
            return (time.monotonic() - ts) > self.COOLDOWN

    def should_pull(self, doc_id: str) -> bool:
        """Return True if this doc was NOT recently pushed (safe to pull)."""
        with self._lock:
            ts = self._pushed.get(doc_id)
            if ts is None:
                return True
            return (time.monotonic() - ts) > self.COOLDOWN


# --- Errors ---


class ConflictError(Exception):
    """Raised on CouchDB 409 conflict."""
    pass


# --- CouchDB client ---


class CouchDB:
    def __init__(self, url: str, database: str, user: str, password: str):
        self.url = url.rstrip("/")
        self.database = database
        self.base = f"{self.url}/{database}"
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()

    def _request(self, path: str, method: str = "GET", body: bytes = None):
        url = f"{self.base}{path}"
        req = Request(url, data=body, method=method)
        req.add_header("Authorization", f"Basic {self.auth}")
        req.add_header("Accept", "application/json")
        if body:
            req.add_header("Content-Type", "application/json")
        try:
            with urlopen(req) as resp:
                return json.loads(resp.read())
        except HTTPError as e:
            if e.code == 409:
                raise ConflictError(f"409 Conflict: {url}")
            raise

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
        return [row["doc"] for row in data["rows"] if row.get("doc")]

    def put_doc(self, doc: dict) -> dict:
        """PUT a document (create or update). Returns response with id/rev."""
        doc_id = doc["_id"]
        return self._request(
            f"/{quote(doc_id, safe='')}",
            method="PUT",
            body=json.dumps(doc).encode(),
        )

    def delete_doc(self, doc_id: str, rev: str) -> dict:
        """DELETE a document by id and rev."""
        return self._request(
            f"/{quote(doc_id, safe='')}?rev={quote(rev, safe='')}",
            method="DELETE",
        )

    def put_docs_bulk(self, docs: list[dict]) -> list[dict]:
        """POST to _bulk_docs for batch writes."""
        return self._request(
            "/_bulk_docs",
            method="POST",
            body=json.dumps({"docs": docs}).encode(),
        )

    def changes_stream(self, since: str = "now", heartbeat: int = 10000):
        """Yield change dicts from a continuous _changes feed."""
        parsed = urlparse(self.base)

        while True:
            path = f"{parsed.path}/_changes?feed=continuous&since={since}&heartbeat={heartbeat}"
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

                # Read byte-by-byte to handle chunked transfer encoding
                buf = b""
                while True:
                    byte = resp.read(1)
                    if not byte:
                        break
                    if byte == b"\n":
                        line = buf.strip()
                        buf = b""
                        if not line:
                            continue  # heartbeat
                        try:
                            change = json.loads(line)
                            if "last_seq" in change:
                                since = change["last_seq"]
                            elif "seq" in change:
                                since = change["seq"]
                                yield change
                        except json.JSONDecodeError:
                            pass
                    else:
                        buf += byte
            except Exception as e:
                log.warning("Changes feed disconnected: %s. Reconnecting in 5s...", e)
                time.sleep(5)


# --- Webhooks ---


class WebhookNotifier:
    def __init__(self, urls: list[str], secret: str = ""):
        self.urls = urls
        self.secret = secret.encode() if secret else b""

    def notify(self, event: str, files: list[dict]):
        """Send webhook notification. Non-blocking, fires in background."""
        if not self.urls:
            return
        payload = json.dumps({
            "event": event,
            "timestamp": time.time(),
            "files": files,
        }).encode()

        for url in self.urls:
            threading.Thread(
                target=self._send, args=(url, payload), daemon=True
            ).start()

    def _send(self, url: str, payload: bytes):
        try:
            req = Request(url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", "obsidian-livesync-materializer")
            if self.secret:
                sig = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
                req.add_header("X-Webhook-Signature", f"sha256={sig}")
            with urlopen(req, timeout=10) as resp:
                log.debug("Webhook %s: %d", url, resp.status)
        except Exception as e:
            log.warning("Webhook %s failed: %s", url, e)


# --- FileSystem Scanner ---

TEXT_EXTENSIONS = {".md", ".txt", ".json", ".csv", ".xml", ".html", ".css", ".js",
                   ".ts", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
                   ".sh", ".bash", ".py", ".rb", ".pl", ".r", ".sql", ".svg"}
TEXT_CHUNK_SIZE = 1000  # characters
BINARY_CHUNK_SIZE = 100 * 1024  # 100KB


class FileSystemScanner:
    """Polls output_dir for filesystem changes in push/both directories."""

    def __init__(self, output_dir: Path, fs_state: dict, sync_rules: SyncRuleEngine,
                 sync_guard: SyncGuard, push_callback, delete_callback,
                 interval: float = 2.0):
        self.output_dir = output_dir
        self.fs_state = fs_state
        self.sync_rules = sync_rules
        self.sync_guard = sync_guard
        self.push_callback = push_callback
        self.delete_callback = delete_callback
        self.interval = interval
        self._stop = threading.Event()

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        return t

    def _run(self):
        while not self._stop.is_set():
            try:
                self._scan()
            except Exception as e:
                log.error("FileSystemScanner error: %s", e)
            self._stop.wait(self.interval)

    def _scan(self):
        # Detect creates and updates
        seen = set()
        for path in self.output_dir.rglob("*"):
            if not path.is_file():
                continue
            rel = str(path.relative_to(self.output_dir))
            seen.add(rel)
            if not self.sync_rules.should_push(rel):
                continue
            if not self.sync_guard.should_push(rel):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            old = self.fs_state.get(rel)
            if old and old[0] == stat.st_mtime and old[1] == stat.st_size:
                continue
            # File is new or changed
            try:
                self.push_callback(rel)
                self.fs_state[rel] = (stat.st_mtime, stat.st_size)
            except Exception as e:
                log.error("Push failed for %s: %s", rel, e)

        # Detect deletes
        for rel in list(self.fs_state.keys()):
            if rel not in seen and self.sync_rules.should_push(rel):
                try:
                    self.delete_callback(rel)
                except Exception as e:
                    log.error("Push delete failed for %s: %s", rel, e)
                self.fs_state.pop(rel, None)

    def stop(self):
        self._stop.set()


# --- Materializer ---


class Materializer:
    def __init__(self, db: CouchDB, output_dir: Path, decrypt_fn=None,
                 encrypt_fn=None, webhook: WebhookNotifier = None,
                 sync_rules: SyncRuleEngine = None, sync_guard: SyncGuard = None):
        self.db = db
        self.output_dir = output_dir
        self.decrypt_fn = decrypt_fn
        self.encrypt_fn = encrypt_fn
        self.webhook = webhook
        self.sync_rules = sync_rules
        self.sync_guard = sync_guard
        # In-memory index: doc_id -> metadata doc
        self.file_index: dict[str, dict] = {}
        # Filesystem state: rel_path -> (mtime, size)
        self.fs_state: dict[str, tuple] = {}

    @staticmethod
    def _is_binary(rel_path: str) -> bool:
        ext = os.path.splitext(rel_path)[1].lower()
        return ext not in TEXT_EXTENSIONS

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
                try:
                    mtime_sec = mtime / 1000.0
                    os.utime(out_path, (mtime_sec, mtime_sec))
                except OSError:
                    pass  # can't set mtime on files owned by others

            # Update sync state
            if self.sync_guard:
                self.sync_guard.mark_pulled(file_path)
            try:
                stat = out_path.stat()
                self.fs_state[file_path] = (stat.st_mtime, stat.st_size)
            except OSError:
                pass

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

        # Update sync state
        if self.sync_guard:
            self.sync_guard.mark_pulled(file_path)
        self.fs_state.pop(file_path, None)

    def split_into_chunks(self, content: str, is_binary: bool) -> list[str]:
        """Split content into chunks for CouchDB storage."""
        chunk_size = BINARY_CHUNK_SIZE if is_binary else TEXT_CHUNK_SIZE
        chunks = []
        for i in range(0, len(content), chunk_size):
            chunks.append(content[i:i + chunk_size])
        return chunks if chunks else [""]

    def push_file(self, rel_path: str):
        """Read a file from disk and push it to CouchDB."""
        abs_path = self.output_dir / rel_path
        if not abs_path.exists():
            return

        is_binary = self._is_binary(rel_path)
        try:
            if is_binary:
                raw_bytes = abs_path.read_bytes()
                content = base64.b64encode(raw_bytes).decode("ascii")
                file_type = "newnote"
            else:
                content = abs_path.read_text(encoding="utf-8")
                file_type = "plain"
        except Exception as e:
            log.error("Failed to read %s: %s", rel_path, e)
            return

        chunks_data = self.split_into_chunks(content, is_binary)

        # Build chunk docs
        chunk_ids = []
        chunk_docs = []
        for chunk_text in chunks_data:
            if self.encrypt_fn:
                encrypted = self.encrypt_fn(chunk_text)
                chunk_id = "h:+" + hashlib.sha256(encrypted.encode("utf-8")).hexdigest()
                chunk_docs.append({
                    "_id": chunk_id,
                    "data": encrypted,
                    "type": "leaf",
                    "e_": True,
                })
            else:
                chunk_id = "h:" + hashlib.sha256(chunk_text.encode("utf-8")).hexdigest()
                chunk_docs.append({
                    "_id": chunk_id,
                    "data": chunk_text,
                    "type": "leaf",
                })
            chunk_ids.append(chunk_id)

        # Write chunks via bulk docs (conflicts are OK — content-addressed)
        if chunk_docs:
            try:
                results = self.db.put_docs_bulk(chunk_docs)
                for r in results:
                    if r.get("error") and r["error"] != "conflict":
                        log.warning("Chunk write error for %s: %s", rel_path, r)
            except Exception as e:
                log.error("Failed to write chunks for %s: %s", rel_path, e)
                return

        # Build metadata doc
        stat = abs_path.stat()
        mtime_ms = int(stat.st_mtime * 1000)
        meta = {
            "_id": rel_path,
            "type": file_type,
            "path": rel_path,
            "children": chunk_ids,
            "mtime": mtime_ms,
            "ctime": mtime_ms,
            "size": stat.st_size,
            "eden": {},
        }

        # Include _rev if doc already exists (needed for update)
        existing = self.file_index.get(rel_path)
        if existing and "_rev" in existing:
            meta["_rev"] = existing["_rev"]

        try:
            resp = self.db.put_doc(meta)
            meta["_rev"] = resp.get("rev")
            self.file_index[rel_path] = meta
            if self.sync_guard:
                self.sync_guard.mark_pushed(rel_path)
            log.info("Pushed: %s (%d chunks)", rel_path, len(chunk_ids))
        except ConflictError:
            self._handle_push_conflict(rel_path, meta)

    def _handle_push_conflict(self, rel_path: str, meta: dict):
        """Re-fetch _rev and retry once on conflict."""
        try:
            existing = self.db.get_doc(rel_path)
            meta["_rev"] = existing["_rev"]
            resp = self.db.put_doc(meta)
            meta["_rev"] = resp.get("rev")
            self.file_index[rel_path] = meta
            if self.sync_guard:
                self.sync_guard.mark_pushed(rel_path)
            log.info("Pushed (retry): %s", rel_path)
        except Exception as e:
            log.error("Push conflict retry failed for %s: %s", rel_path, e)

    def push_delete(self, rel_path: str):
        """Delete a metadata doc from CouchDB."""
        existing = self.file_index.get(rel_path)
        if not existing or "_rev" not in existing:
            try:
                existing = self.db.get_doc(rel_path)
            except Exception:
                log.debug("No CouchDB doc to delete for %s", rel_path)
                return

        try:
            self.db.delete_doc(rel_path, existing["_rev"])
            self.file_index.pop(rel_path, None)
            if self.sync_guard:
                self.sync_guard.mark_pushed(rel_path)
            log.info("Push-deleted: %s", rel_path)
        except ConflictError:
            try:
                existing = self.db.get_doc(rel_path)
                self.db.delete_doc(rel_path, existing["_rev"])
                self.file_index.pop(rel_path, None)
                if self.sync_guard:
                    self.sync_guard.mark_pushed(rel_path)
                log.info("Push-deleted (retry): %s", rel_path)
            except Exception as e:
                log.error("Push delete retry failed for %s: %s", rel_path, e)
        except Exception as e:
            log.error("Failed to push-delete %s: %s", rel_path, e)

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
            # Always index metadata for _rev tracking
            self.file_index[meta["_id"]] = meta
            file_path = meta.get("path", meta["_id"])
            # Skip writing files in push-only directories
            if self.sync_rules and not self.sync_rules.should_pull(file_path):
                continue
            if self.write_file(meta):
                written += 1
            else:
                errors += 1

        # Clean up files that no longer exist in DB (only in pull dirs)
        existing_paths = {m.get("path", m["_id"]) for m in metadata}
        for path in list(self.output_dir.rglob("*")):
            if path.is_file():
                rel = str(path.relative_to(self.output_dir))
                if rel not in existing_paths:
                    # Only clean up files in pull directories
                    if self.sync_rules and not self.sync_rules.should_pull(rel):
                        continue
                    path.unlink()
                    log.info("Cleaned up stale file: %s", rel)

        log.info("Full sync done: %d files, %d errors", written, errors)

        # Get current update_seq
        info = self.db._request("")
        return str(info.get("update_seq", "now"))

    def init_fs_state(self):
        """Initialize fs_state by scanning output_dir."""
        for path in self.output_dir.rglob("*"):
            if path.is_file():
                rel = str(path.relative_to(self.output_dir))
                try:
                    stat = path.stat()
                    self.fs_state[rel] = (stat.st_mtime, stat.st_size)
                except OSError:
                    pass

    def process_changes(self, changed_ids: set[str]):
        """Process a batch of changed document IDs."""
        if not changed_ids:
            return

        # Fetch the changed docs
        docs = self.db.get_docs_bulk(list(changed_ids))
        doc_map = {d["_id"]: d for d in docs}

        files_to_update = set()
        deleted_files = []

        for doc_id in changed_ids:
            doc = doc_map.get(doc_id)

            # Doc not returned (deleted or purged)
            if not doc:
                old_meta = self.file_index.get(doc_id)
                if old_meta:
                    file_path = old_meta.get("path", doc_id)
                    can_pull = True
                    if self.sync_rules and not self.sync_rules.should_pull(file_path):
                        can_pull = False
                    if self.sync_guard and not self.sync_guard.should_pull(doc_id):
                        can_pull = False
                    if can_pull:
                        deleted_files.append(file_path)
                        self.delete_file(doc_id)
                    else:
                        self.file_index.pop(doc_id, None)
                continue

            doc_type = doc.get("type")
            deleted = doc.get("_deleted") or doc.get("deleted")

            if doc_type in ("plain", "newnote"):
                if deleted or not doc.get("children"):
                    old_meta = self.file_index.get(doc_id)
                    if old_meta:
                        file_path = old_meta.get("path", doc_id)
                    else:
                        file_path = doc.get("path", doc_id)
                    can_pull = True
                    if self.sync_rules and not self.sync_rules.should_pull(file_path):
                        can_pull = False
                    if self.sync_guard and not self.sync_guard.should_pull(doc_id):
                        can_pull = False
                    if can_pull:
                        if old_meta:
                            deleted_files.append(file_path)
                        self.delete_file(doc_id)
                    else:
                        self.file_index.pop(doc_id, None)
                else:
                    # Always update index for _rev tracking
                    self.file_index[doc_id] = doc
                    files_to_update.add(doc_id)
            elif doc_type == "leaf":
                # A chunk changed — find which files reference it
                for fid, meta in self.file_index.items():
                    if doc_id in meta.get("children", []):
                        files_to_update.add(fid)

        updated_files = []
        for fid in files_to_update:
            meta = self.file_index.get(fid)
            if meta:
                path = meta.get("path", fid)
                # Check sync rules and guard
                if self.sync_rules and not self.sync_rules.should_pull(path):
                    continue
                if self.sync_guard and not self.sync_guard.should_pull(fid):
                    continue
                if self.write_file(meta):
                    log.info("Updated: %s", path)
                    updated_files.append(path)
                else:
                    log.error("Failed to update: %s", path)

        # Send webhook notifications
        if self.webhook:
            wh_files = []
            for p in updated_files:
                wh_files.append({"path": p, "action": "updated"})
            for p in deleted_files:
                wh_files.append({"path": p, "action": "deleted"})
            if wh_files:
                self.webhook.notify("files_changed", wh_files)


def main():
    url = os.environ.get("COUCHDB_URL", "http://localhost:5984")
    database = os.environ.get("COUCHDB_DATABASE", "obsidiandb")
    user = os.environ.get("COUCHDB_USER", "")
    password = os.environ.get("COUCHDB_PASSWORD", "")
    passphrase = os.environ.get("E2EE_PASSPHRASE", "")
    pbkdf2_salt_b64 = os.environ.get("PBKDF2_SALT", "")
    output_dir = Path(os.environ.get("OUTPUT_DIR", "/output"))
    debounce = float(os.environ.get("DEBOUNCE", "1"))
    sync_mode = os.environ.get("SYNC_MODE", "pull").lower()
    sync_rules_str = os.environ.get("SYNC_RULES", "")
    push_interval = float(os.environ.get("PUSH_INTERVAL", "2"))

    if sync_mode not in ("pull", "push", "both"):
        log.error("SYNC_MODE must be 'pull', 'push', or 'both'")
        sys.exit(1)

    if not user or not password:
        log.error("COUCHDB_USER and COUCHDB_PASSWORD are required")
        sys.exit(1)

    db = CouchDB(url, database, user, password)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Encryption
    decrypt_fn = None
    encrypt_fn = None
    if passphrase and pbkdf2_salt_b64:
        pbkdf2_salt = base64.b64decode(pbkdf2_salt_b64)
        master_key = derive_master_key(passphrase, pbkdf2_salt)
        decrypt_fn = make_decryptor(master_key)
        encrypt_fn = make_encryptor(master_key)

    # Webhooks
    webhook = None
    webhook_urls = os.environ.get("WEBHOOK_URL", "")
    webhook_secret = os.environ.get("WEBHOOK_SECRET", "")
    if webhook_urls:
        urls = [u.strip() for u in webhook_urls.split(",") if u.strip()]
        webhook = WebhookNotifier(urls, webhook_secret)
        log.info("Webhooks enabled: %d URL(s)", len(urls))

    # Sync rules and guard
    sync_rules = SyncRuleEngine(sync_mode, sync_rules_str)
    sync_guard = SyncGuard()
    log.info("Sync mode: %s", sync_mode)
    if sync_rules_str:
        log.info("Sync rules: %s", sync_rules_str)

    mat = Materializer(db, output_dir, decrypt_fn, encrypt_fn, webhook, sync_rules, sync_guard)

    # Full sync first
    last_seq = mat.full_sync()

    # Initialize filesystem state
    mat.init_fs_state()

    # Start filesystem scanner if push is enabled
    scanner = None
    if sync_rules.has_push_rules():
        log.info("Starting filesystem scanner (interval=%.1fs)...", push_interval)
        scanner = FileSystemScanner(
            output_dir, mat.fs_state, sync_rules, sync_guard,
            mat.push_file, mat.push_delete, push_interval,
        )
        scanner.start()

    # Start _changes watcher if pull is enabled
    if sync_rules.has_pull_rules():
        log.info("Watching for changes (since=%s, debounce=%.1fs)...", last_seq, debounce)

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
    else:
        # Push-only mode: keep main thread alive
        log.info("Push-only mode, no _changes feed. Scanner running...")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            log.info("Shutting down...")


if __name__ == "__main__":
    main()
