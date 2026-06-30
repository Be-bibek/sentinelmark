# Disaster Recovery Runbook

This document describes the procedures for backup, restore, zero-downtime deployment, and rollback for SentinelMark.

## Database Backups

### Manual Backup
```bash
./scripts/backup.sh
```
Creates a timestamped `.sql.gz` file in `./backups/`. Retains the last 14 backups automatically.

### Automated Backups
Add a cron job on your server or use the GitHub Actions `security.yml` schedule:
```bash
0 2 * * * /app/scripts/backup.sh >> /var/log/sm-backup.log 2>&1
```

### Restore from Backup
```bash
./scripts/restore.sh ./backups/sentinelmark_20260630_010000.sql.gz
```
> ⚠️ This drops and recreates the database. A 5-second safety window is provided before destructive operations begin.

---

## Zero-Downtime Deployments

SentinelMark uses rolling updates. The key principle: **run migrations before deploying new app code**.

### Deployment Order
1. Run `cargo sqlx migrate run` against the live database.
2. Deploy the new API Gateway container (Docker Swarm / Kubernetes rolling update).
3. Verify `/health/ready` returns `200` on the new instance.
4. Shift traffic.

### Rollback
If the new deployment fails:
1. Re-deploy the previous image tag.
2. If the migration is irreversible, restore from the pre-migration backup.

---

## Secrets Management

- **Never** commit secrets to git. Use `.env` locally and environment variables in CI/CD.
- Validate all required secrets before any deployment:
  ```bash
  ./scripts/validate_env.sh
  ```
- For production, use a secrets manager (AWS Secrets Manager, HashiCorp Vault, or GitHub Secrets).

---

## Migration Rollback

SentinelMark uses `sqlx` migrations. Migrations are additive by design (no DROP in forward migrations). To roll back a schema change, write a new "down" migration and run it:

```bash
# Add a reverting migration
sqlx migrate add revert_xxx

# Run it
cargo sqlx migrate run
```
