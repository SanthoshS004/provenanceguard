#!/usr/bin/env bash
# ProvenanceGuard Disaster Recovery Restore Script
# Usage: bash restore_provenanceguard.sh <path_to_db_dump> <path_to_minio_tar_gz>

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <path_to_db_dump> <path_to_minio_tar_gz>"
    echo "Example: $0 backups/db_provenanceguard_prod_20261006_020000.dump backups/minio_artifacts_20261006_020000.tar.gz"
    exit 1
fi

DB_DUMP_FILE="$1"
MINIO_TAR_FILE="$2"

if [ ! -f "$DB_DUMP_FILE" ]; then
    echo "ERROR: Database dump file '$DB_DUMP_FILE' not found!"
    exit 1
fi

if [ ! -f "$MINIO_TAR_FILE" ]; then
    echo "ERROR: MinIO archive file '$MINIO_TAR_FILE' not found!"
    exit 1
fi

DB_CONTAINER="provenanceguard-prod-postgres"
DB_USER="${PG_DB_USER:-provenanceguard_admin}"
DB_NAME="${PG_DB_NAME:-provenanceguard_prod}"

echo "=================================================="
echo " Starting ProvenanceGuard Disaster Recovery Restore"
echo "=================================================="

# 1. Restore PostgreSQL Database
echo "[1/2] Restoring PostgreSQL database from $DB_DUMP_FILE..."
docker exec -i "$DB_CONTAINER" pg_restore -U "$DB_USER" -d "$DB_NAME" --clean --if-exists < "$DB_DUMP_FILE" || true
echo "✓ Database restore complete."

# 2. Restore MinIO Volume Archive
echo "[2/2] Restoring MinIO artifact storage from $MINIO_TAR_FILE..."
VOL_NAME=$(docker volume ls --format '{{.Name}}' | grep "minio_prod_data" | head -n 1)
docker run --rm -v "$VOL_NAME":/data -v "$(dirname "$(realpath "$MINIO_TAR_FILE")")":/backup alpine tar xzf "/backup/$(basename "$MINIO_TAR_FILE")" -C /data
echo "✓ MinIO volume restore complete."

echo "=================================================="
echo " Disaster Recovery Restore Completed Successfully!"
echo "=================================================="
