#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SentinelMark — Database Backup Script
# Usage: ./scripts/backup.sh
# Creates a timestamped pg_dump and optionally uploads to S3.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DB_USER="${POSTGRES_USER:-sentinelmark}"
DB_NAME="${POSTGRES_DB:-sentinelmark}"
DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5432}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/sentinelmark_${TIMESTAMP}.sql.gz"

mkdir -p "$BACKUP_DIR"

echo "[backup] Starting database backup: ${BACKUP_FILE}"
PGPASSWORD="${POSTGRES_PASSWORD:-sentinelmark}" \
  pg_dump \
    --host="${DB_HOST}" \
    --port="${DB_PORT}" \
    --username="${DB_USER}" \
    --format=plain \
    --no-owner \
    --no-acl \
    "${DB_NAME}" | gzip > "${BACKUP_FILE}"

echo "[backup] Backup complete: $(du -sh "${BACKUP_FILE}" | cut -f1)"

# Optional: upload to S3
if [ -n "${S3_BUCKET:-}" ]; then
  echo "[backup] Uploading to s3://${S3_BUCKET}/backups/"
  aws s3 cp "${BACKUP_FILE}" "s3://${S3_BUCKET}/backups/$(basename "${BACKUP_FILE}")"
  echo "[backup] Upload complete"
fi

# Cleanup: keep only the last 14 backups locally
find "$BACKUP_DIR" -name "sentinelmark_*.sql.gz" | sort -r | tail -n +15 | xargs -r rm --
echo "[backup] Old backups pruned. Done."
