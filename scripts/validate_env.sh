#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SentinelMark — Environment Validation Script
# Run before deploying to verify all required env vars are present and valid.
# Usage: ./scripts/validate_env.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0

check_var() {
  local name="$1"
  local value="${!name:-}"
  if [ -z "$value" ]; then
    echo -e "${RED}[MISSING]${NC} ${name}"
    ERRORS=$((ERRORS + 1))
  else
    echo -e "${GREEN}[OK]${NC}     ${name}"
  fi
}

echo "═══════════════════════════════════════════════"
echo "  SentinelMark Environment Validation"
echo "═══════════════════════════════════════════════"

echo ""
echo "▶ Database"
check_var DATABASE_URL
check_var POSTGRES_USER
check_var POSTGRES_PASSWORD
check_var POSTGRES_DB

echo ""
echo "▶ Cache"
check_var REDIS_URL

echo ""
echo "▶ Authentication"
check_var JWT_SECRET

echo ""
echo "▶ Observability"
check_var OTEL_EXPORTER_OTLP_ENDPOINT

echo ""
echo "═══════════════════════════════════════════════"
if [ "$ERRORS" -gt 0 ]; then
  echo -e "${RED}FAILED: ${ERRORS} required variable(s) missing.${NC}"
  exit 1
else
  echo -e "${GREEN}PASSED: All required environment variables present.${NC}"
fi
