# obsidian-livesync-materializer

Materializes Obsidian vault files from a CouchDB [LiveSync](https://github.com/vrtmrz/obsidian-livesync) database to a local directory. Supports E2EE (HKDF/V2) encrypted vaults and bidirectional sync.

## How it works

1. On startup, performs a full sync — fetches all documents, decrypts chunks, writes files
2. Then watches the CouchDB `_changes` feed for real-time updates (configurable debounce)
3. Handles file creation, modification, and deletion
4. Optionally scans the filesystem for changes and pushes them back to CouchDB

## Bidirectional sync

By default, the materializer only pulls from CouchDB to disk (fully backward compatible). You can enable push or bidirectional sync using `SYNC_MODE` and `SYNC_RULES`.

**Sync modes:**

| Mode | Direction | Use case |
|---|---|---|
| `pull` | CouchDB -> disk | Default. Read-only mirror of your vault |
| `push` | Disk -> CouchDB | Agent-only folders. Files written to disk appear in Obsidian |
| `both` | Bidirectional | Shared folders. Edits from either side sync to the other |

**Per-directory rules** override the global mode using glob patterns:

```
SYNC_RULES=agents/*:push,shared/*:both,private/*:pull
```

Rules are evaluated in order; the first matching pattern wins. Paths that match no rule use `SYNC_MODE`.

### Sync loop prevention

The materializer prevents infinite loops with a two-layer guard:
1. **Time-based cooldown** (5s) — a file just pulled from CouchDB won't be pushed back, and vice versa
2. **mtime tracking** — the filesystem scanner skips files whose mtime hasn't changed since the last pull

## Docker image

```
ghcr.io/nikitatsym/obsidian-livesync-materializer:latest
```

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `COUCHDB_URL` | yes | `http://localhost:5984` | CouchDB URL |
| `COUCHDB_DATABASE` | yes | `obsidiandb` | Database name |
| `COUCHDB_USER` | yes | | CouchDB username |
| `COUCHDB_PASSWORD` | yes | | CouchDB password |
| `E2EE_PASSPHRASE` | if encrypted | | E2EE passphrase from LiveSync settings |
| `PBKDF2_SALT` | if encrypted | | Base64 PBKDF2 salt from LiveSync settings |
| `OUTPUT_DIR` | no | `/output` | Output directory inside container |
| `DEBOUNCE` | no | `1` | Debounce interval in seconds for changes |
| `WEBHOOK_URL` | no | | Comma-separated URLs to POST on file changes |
| `WEBHOOK_SECRET` | no | | HMAC-SHA256 secret for signing webhook payloads |
| `SYNC_MODE` | no | `pull` | Global sync mode: `pull`, `push`, or `both` |
| `SYNC_RULES` | no | | Comma-separated `pattern:mode` pairs (see below) |
| `PUSH_INTERVAL` | no | `2` | Filesystem scan interval in seconds for push |

### Where to find E2EE parameters

In Obsidian LiveSync plugin settings -> "Remote Configuration" -> check the setup URI or look at the CouchDB document `obsidian_livesync_sync_parameters`.

### SYNC_RULES format

Comma-separated rules, each in `pattern:mode` format. Patterns use shell glob syntax (`*`, `?`, `[...]`).

```
SYNC_RULES=agents/*:push,shared/*:both,archive/*:pull
```

- `agents/*:push` — files in `agents/` are pushed from disk to CouchDB only
- `shared/*:both` — files in `shared/` sync bidirectionally
- `archive/*:pull` — files in `archive/` are pulled from CouchDB only

## Docker Compose examples

### Pull only (default, backward compatible)

```yaml
services:
  couchdb:
    image: couchdb:latest
    restart: unless-stopped
    environment:
      - COUCHDB_USER=admin
      - COUCHDB_PASSWORD=secret
    volumes:
      - couchdb_data:/opt/couchdb/data

  materialize:
    image: ghcr.io/nikitatsym/obsidian-livesync-materializer:latest
    restart: unless-stopped
    depends_on:
      - couchdb
    environment:
      - COUCHDB_URL=http://couchdb:5984
      - COUCHDB_DATABASE=obsidiandb
      - COUCHDB_USER=admin
      - COUCHDB_PASSWORD=secret
      - E2EE_PASSPHRASE=your-passphrase
      - PBKDF2_SALT=your-base64-salt
      - DEBOUNCE=1
    volumes:
      - ./vault:/output

volumes:
  couchdb_data:
```

### Bidirectional with per-directory rules

```yaml
services:
  materialize:
    image: ghcr.io/nikitatsym/obsidian-livesync-materializer:latest
    restart: unless-stopped
    environment:
      - COUCHDB_URL=http://couchdb:5984
      - COUCHDB_DATABASE=obsidiandb
      - COUCHDB_USER=admin
      - COUCHDB_PASSWORD=secret
      - E2EE_PASSPHRASE=your-passphrase
      - PBKDF2_SALT=your-base64-salt
      - SYNC_MODE=pull
      - SYNC_RULES=agents/*:push,shared/*:both
      - PUSH_INTERVAL=2
    volumes:
      - ./vault:/output
```

In this setup:
- `agents/` — write files here from scripts/agents, they sync to Obsidian
- `shared/` — edits from Obsidian or disk both sync
- Everything else — pulled from Obsidian (read-only mirror)

After starting, your vault files will appear in `./vault/` and update in real-time as you edit in Obsidian.

## Optional: S3 backup sidecar

Add an rclone container to periodically archive the vault to S3:

```yaml
  backup-s3:
    image: rclone/rclone:latest
    restart: unless-stopped
    depends_on:
      - materialize
    volumes:
      - ./vault:/vault:ro
      - ./rclone.conf:/config/rclone/rclone.conf:ro
      - ./backup.sh:/backup.sh:ro
    entrypoint: []
    command: ["sh", "/backup.sh"]
```

See [backup.sh](backup.sh) for the script — creates hourly tar.gz archives, prunes by age and total size.

## Webhooks

Set `WEBHOOK_URL` to get notified when vault files change. Multiple URLs can be comma-separated.

Payload (`POST`, `Content-Type: application/json`):

```json
{
  "event": "files_changed",
  "timestamp": 1772361170.267,
  "files": [
    {"path": "Diary/2026-03-01.md", "action": "updated"},
    {"path": "old-note.md", "action": "deleted"}
  ]
}
```

If `WEBHOOK_SECRET` is set, each request includes an `X-Webhook-Signature` header:

```
X-Webhook-Signature: sha256=<HMAC-SHA256 hex digest of the body>
```

Verify it like GitHub webhooks:

```python
import hmac, hashlib
expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
assert signature == f"sha256={expected}"
```

## License

MIT
