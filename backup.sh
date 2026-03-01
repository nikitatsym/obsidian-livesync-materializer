#!/bin/sh
set -e

VAULT_DIR="${VAULT_DIR:-/vault}"
S3_BUCKET="${S3_BUCKET:-backups}"
S3_PREFIX="${S3_PREFIX:-obsidian-vault}"
MAX_DAYS="${MAX_DAYS:-20}"
MAX_BYTES="${MAX_BYTES:-10737418240}"
INTERVAL="${BACKUP_INTERVAL:-3600}"

apk add --no-cache python3 > /dev/null 2>&1 || true

while true; do
    STAMP=$(date +%Y-%m-%d_%H-%M)
    ARCHIVE="vault-${STAMP}.tar.gz"
    FILE_COUNT=$(find "$VAULT_DIR" -type f 2>/dev/null | wc -l)

    if [ "$FILE_COUNT" -eq 0 ]; then
        echo "[$(date)] Vault empty, skipping"
        sleep "$INTERVAL"
        continue
    fi

    echo "[$(date)] Backup: $ARCHIVE ($FILE_COUNT files)"
    tar -czf "/tmp/$ARCHIVE" -C "$VAULT_DIR" .
    rclone copy "/tmp/$ARCHIVE" "garage:${S3_BUCKET}/${S3_PREFIX}/" --verbose 2>&1
    rm -f "/tmp/$ARCHIVE"

    echo "[$(date)] Pruning old backups..."
    rclone lsjson "garage:${S3_BUCKET}/${S3_PREFIX}/" 2>/dev/null | python3 -c "
import json, sys, datetime
items = json.load(sys.stdin)
items.sort(key=lambda x: x['Name'], reverse=True)
cutoff = datetime.datetime.now() - datetime.timedelta(days=${MAX_DAYS})
total = 0
for i in items:
    total += i.get('Size', 0)
    try:
        age = datetime.datetime.strptime(i.get('ModTime', '')[:10], '%Y-%m-%d')
    except Exception:
        age = datetime.datetime.now()
    if age < cutoff or total > ${MAX_BYTES}:
        print(i['Name'])
" | while read -r F; do
        echo "[$(date)] Deleting: $F"
        rclone deletefile "garage:${S3_BUCKET}/${S3_PREFIX}/$F" 2>&1
    done

    echo "[$(date)] Done. Sleeping ${INTERVAL}s..."
    sleep "$INTERVAL"
done
