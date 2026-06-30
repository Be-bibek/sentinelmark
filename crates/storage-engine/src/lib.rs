//! Storage Engine — SQLx-backed PostgreSQL repository implementations.
//!
//! Uses sqlx::query (non-macro) for full offline compilation compatibility.
//! No live database required for cargo check / cargo build.

use audit_engine::AuditEntry;
use behavior_engine::BehaviorProfile;
use chrono::{DateTime, Utc};
use sentinelmark_core::UserId;
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// TRAITS
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
pub trait ProfileRepository: Send + Sync {
    async fn get_profile(&self, user_id: &UserId) -> Result<Option<BehaviorProfile>, StorageError>;
    async fn save_profile(
        &self,
        user_id: &UserId,
        profile: &BehaviorProfile,
    ) -> Result<(), StorageError>;
    async fn ensure_user(&self, user_id: &UserId) -> Result<(), StorageError>;
}

#[async_trait::async_trait]
pub trait AuditRepository: Send + Sync {
    async fn record_decision(
        &self,
        entry: &AuditEntry,
        risk_score: f64,
        explanation: String,
        eval_time_ms: i64,
    ) -> Result<Uuid, StorageError>;
    async fn list_for_user(
        &self,
        user_id: &UserId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditRow>, StorageError>;
}

#[async_trait::async_trait]
pub trait TelemetryRepository: Send + Sync {
    async fn insert_event(
        &self,
        user_id: &UserId,
        event: &TelemetryRow,
    ) -> Result<Uuid, StorageError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// ROW TYPES
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRow {
    pub id: Uuid,
    pub user_id: String,
    pub trust_score: f64,
    pub risk_score: f64,
    pub decision: String,
    pub anomalies: Vec<String>,
    pub policy_decision: String,
    pub explanation: String,
    pub evaluation_time_ms: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TelemetryRow {
    pub device_id: String,
    pub browser_fingerprint: String,
    pub ip_address: String,
    pub geo_region: String,
    pub action_type: String,
    pub transaction_amount: Option<f64>,
    pub session_duration_secs: Option<i64>,
    pub recorded_at: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ERRORS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("User not found: {0}")]
    UserNotFound(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// IMPLEMENTATION
// ─────────────────────────────────────────────────────────────────────────────

pub struct PostgresStorage {
    pub pool: PgPool,
}

impl PostgresStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ProfileRepository for PostgresStorage {
    async fn ensure_user(&self, user_id: &UserId) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO users (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING")
            .bind(&user_id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_profile(&self, user_id: &UserId) -> Result<Option<BehaviorProfile>, StorageError> {
        let row: Option<(serde_json::Value, serde_json::Value, f64)> = sqlx::query_as(
            "SELECT known_devices, known_regions, avg_transaction_amount
             FROM behavior_profiles WHERE user_id = $1",
        )
        .bind(&user_id.0)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            None => Ok(None),
            Some((devices_val, regions_val, avg)) => {
                let devices: Vec<String> = serde_json::from_value(devices_val)?;
                let regions: Vec<String> = serde_json::from_value(regions_val)?;
                Ok(Some(BehaviorProfile {
                    known_devices: devices.into_iter().collect::<HashSet<_>>(),
                    known_regions: regions.into_iter().collect::<HashSet<_>>(),
                    avg_transaction_amount: avg,
                }))
            }
        }
    }

    async fn save_profile(
        &self,
        user_id: &UserId,
        profile: &BehaviorProfile,
    ) -> Result<(), StorageError> {
        let devices: Vec<&str> = profile.known_devices.iter().map(|s| s.as_str()).collect();
        let regions: Vec<&str> = profile.known_regions.iter().map(|s| s.as_str()).collect();
        let devices_json = serde_json::to_value(&devices)?;
        let regions_json = serde_json::to_value(&regions)?;

        sqlx::query(
            r#"INSERT INTO behavior_profiles (user_id, known_devices, known_regions, avg_transaction_amount)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (user_id) DO UPDATE
               SET known_devices = $2, known_regions = $3,
                   avg_transaction_amount = $4, updated_at = NOW()"#,
        )
        .bind(&user_id.0)
        .bind(devices_json)
        .bind(regions_json)
        .bind(profile.avg_transaction_amount)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl AuditRepository for PostgresStorage {
    async fn record_decision(
        &self,
        entry: &AuditEntry,
        risk_score: f64,
        explanation: String,
        eval_time_ms: i64,
    ) -> Result<Uuid, StorageError> {
        let decision_str = format!("{:?}", entry.decision);
        let anomalies_json = serde_json::to_value(&entry.reasons)?;

        let row: (Uuid,) = sqlx::query_as(
            r#"INSERT INTO audit_logs
               (user_id, trust_score, risk_score, decision, anomalies, policy_decision, explanation, evaluation_time_ms)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING id"#,
        )
        .bind(&entry.user_id.0)
        .bind(entry.trust_score)
        .bind(risk_score)
        .bind(&decision_str)
        .bind(anomalies_json)
        .bind(&decision_str)
        .bind(&explanation)
        .bind(eval_time_ms)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0)
    }

    async fn list_for_user(
        &self,
        user_id: &UserId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditRow>, StorageError> {
        let rows: Vec<(
            Uuid,
            String,
            f64,
            f64,
            String,
            serde_json::Value,
            String,
            String,
            Option<i64>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            r#"SELECT id, user_id, trust_score, risk_score, decision,
                          anomalies, policy_decision, explanation,
                          evaluation_time_ms, created_at
                   FROM audit_logs
                   WHERE user_id = $1
                   ORDER BY created_at DESC
                   LIMIT $2 OFFSET $3"#,
        )
        .bind(&user_id.0)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let result = rows
            .into_iter()
            .map(
                |(
                    id,
                    uid,
                    trust,
                    risk,
                    decision,
                    anomalies_val,
                    policy,
                    explanation,
                    eval_ms,
                    created_at,
                )| {
                    let anomalies: Vec<String> =
                        serde_json::from_value(anomalies_val).unwrap_or_default();
                    AuditRow {
                        id,
                        user_id: uid,
                        trust_score: trust,
                        risk_score: risk,
                        decision,
                        anomalies,
                        policy_decision: policy,
                        explanation,
                        evaluation_time_ms: eval_ms,
                        created_at,
                    }
                },
            )
            .collect();

        Ok(result)
    }
}

#[async_trait::async_trait]
impl TelemetryRepository for PostgresStorage {
    async fn insert_event(
        &self,
        user_id: &UserId,
        event: &TelemetryRow,
    ) -> Result<Uuid, StorageError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"INSERT INTO telemetry_events
               (user_id, device_id, browser_fingerprint, ip_address, geo_region,
                action_type, transaction_amount, session_duration_secs, recorded_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
               RETURNING id"#,
        )
        .bind(&user_id.0)
        .bind(&event.device_id)
        .bind(&event.browser_fingerprint)
        .bind(&event.ip_address)
        .bind(&event.geo_region)
        .bind(&event.action_type)
        .bind(event.transaction_amount)
        .bind(event.session_duration_secs)
        .bind(event.recorded_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0)
    }
}
