# obsidian-livesync-materializer

Materializes Obsidian vault files from a CouchDB [LiveSync](https://github.com/vrtmrz/obsidian-livesync) database to a local directory. Supports E2EE (HKDF/V2) encrypted vaults.

## How it works

1. On startup, performs a full sync — fetches all documents, decrypts chunks, writes files
2. Then watches the CouchDB `_changes` feed for real-time updates (configurable debounce)
3. Handles file creation, modification, and deletion

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

### Where to find E2EE parameters

In Obsidian LiveSync plugin settings → "Remote Configuration" → check the setup URI or look at the CouchDB document `obsidian_livesync_sync_parameters`.

## Docker Compose example

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
