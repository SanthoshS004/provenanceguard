#!/usr/bin/env bash
# Database & Storage Backup Script for ProvenanceGuard
# Can be scheduled via cron (e.g. 0 2 * * * /opt/provenanceguard/backup_db.sh)

set -euo pipefail

BACKUP_DIR="/opt/provenanceguard/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
mkdir -p "$BACKUP_DIR"

DB_CONTAINER="provenanceguard-prod-postgres"
DB_USER="provenanceguard_admin"
DB_NAME="provenanceguard_prod"

echo "Creating PostgreSQL database dump..."
docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" -F c > "$BACKUP_DIR/provenanceguard_db_$TIMESTAMP.dump"

# Prune backups older than 14 days
find "$BACKUP_DIR" -type f -name "*.dump" -mtime +14 -delete

echo "Backup complete: $BACKUP_DIR/provenanceguard_db_$TIMESTAMP.dump"
