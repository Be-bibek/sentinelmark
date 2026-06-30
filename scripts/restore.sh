#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SentinelMark — Database Restore Script
# Usage: ./scripts/restore.sh ./backups/sentinelmark_20260630_010000.sql.gz
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BACKUP_FILE="${1:-}"
if [ -z "$BACKUP_FILE" ]; then
  echo "[restore] ERROR: No backup file specified."
  echo "  Usage: $0 <backup_file.sql.gz>"
  exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
  echo "[restore] ERROR: File not found: ${BACKUP_FILE}"
  exit 1
fi

DB_USER="${POSTGRES_USER:-sentinelmark}"
DB_NAME="${POSTGRES_DB:-sentinelmark}"
DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5432}"

echo "[restore] WARNING: This will DROP and RECREATE the database '${DB_NAME}'."
echo "[restore] Press CTRL+C within 5 seconds to abort."
sleep 5

echo "[restore] Dropping existing database..."
PGPASSWORD="${POSTGRES_PASSWORD:-sentinelmark}" \
  psql --host="${DB_HOST}" --port="${DB_PORT}" --username="${DB_USER}" \
    -c "DROP DATABASE IF EXISTS ${DB_NAME};" postgres

echo "[restore] Creating database..."
PGPASSWORD="${POSTGRES_PASSWORD:-sentinelmark}" \
  psql --host="${DB_HOST}" --port="${DB_PORT}" --username="${DB_USER}" \
    -c "CREATE DATABASE ${DB_NAME};" postgres

echo "[restore] Restoring from ${BACKUP_FILE}..."
gunzip -c "${BACKUP_FILE}" | \
  PGPASSWORD="${POSTGRES_PASSWORD:-sentinelmark}" \
  psql --host="${DB_HOST}" --port="${DB_PORT}" --username="${DB_USER}" "${DB_NAME}"

echo "[restore] Restore complete."
