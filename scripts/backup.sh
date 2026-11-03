#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p nodekeep-backups
stamp=$(date -u +%Y%m%dT%H%M%SZ)
docker compose exec -T operator python -c 'import sqlite3;src=sqlite3.connect("/data/nodekeep.sqlite3");dest=sqlite3.connect("/data/backup.sqlite3");src.backup(dest);dest.close();src.close()'
docker compose cp operator:/data/backup.sqlite3 "nodekeep-backups/nodekeep-${stamp}.sqlite3"
docker compose exec -T operator rm /data/backup.sqlite3
chmod 600 "nodekeep-backups/nodekeep-${stamp}.sqlite3"
echo "Saved nodekeep-backups/nodekeep-${stamp}.sqlite3"
