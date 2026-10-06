#!/usr/bin/env bash
# ProvenanceGuard Backup Script for PostgreSQL Database & MinIO Storage
# Execute manually or via systemd timer / cron: /opt/provenanceguard/backup_provenanceguard.sh

set -euo pipefail

BACKUP_DIR="/opt/provenanceguard/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RETENTION_DAYS=14

mkdir -p "$BACKUP_DIR"

DB_CONTAINER="provenanceguard-prod-postgres"
DB_USER="${PG_DB_USER:-provenanceguard_admin}"
DB_NAME="${PG_DB_NAME:-provenanceguard_prod}"
MINIO_VOLUME="provenanceguard_minio_prod_data"

echo "=================================================="
echo " Starting ProvenanceGuard Complete Backup          "
echo " Timestamp: $TIMESTAMP                            "
echo "=================================================="

# 1. PostgreSQL Database Dump
echo "[1/2] Creating PostgreSQL database dump..."
if docker ps --format '{{.Names}}' | grep -q "^${DB_CONTAINER}$"; then
    docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" -F c > "$BACKUP_DIR/db_${DB_NAME}_$TIMESTAMP.dump"
    echo "✓ Database dump saved: $BACKUP_DIR/db_${DB_NAME}_$TIMESTAMP.dump"
else
    echo "ERROR: Database container '$DB_CONTAINER' is not running!"
    exit 1
fi

# 2. MinIO Object Storage Volume Archive
echo "[2/2] Archiving MinIO object storage artifacts volume..."
if docker volume ls --format '{{.Name}}' | grep -q "minio_prod_data"; then
    VOL_NAME=$(docker volume ls --format '{{.Name}}' | grep "minio_prod_data" | head -n 1)
    docker run --rm -v "$VOL_NAME":/data -v "$BACKUP_DIR":/backup alpine tar czf "/backup/minio_artifacts_$TIMESTAMP.tar.gz" -C /data .
    echo "✓ MinIO volume archive saved: $BACKUP_DIR/minio_artifacts_$TIMESTAMP.tar.gz"
else
    echo "WARNING: MinIO volume not found. Skipping MinIO archive."
fi

# 3. Prune old backups older than $RETENTION_DAYS
echo "Pruning backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -type f \( -name "*.dump" -o -name "*.tar.gz" \) -mtime "+$RETENTION_DAYS" -delete

echo "=================================================="
echo " Backup Completed Successfully!                   "
echo "=================================================="
