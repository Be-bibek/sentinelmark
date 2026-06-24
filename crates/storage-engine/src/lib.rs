//! Storage Engine
//!
//! Repository layer for behavior profiles, audit logs, and policy history.
//! Uses SQLx + PostgreSQL. All engine logic is stored here; pure engines remain separate.

use std::future::Future;
use sentinelmark_core::UserId;
use audit_engine::AuditEntry;
use behavior_engine::BehaviorProfile;

pub trait ProfileRepository: Send + Sync {
    fn get_profile(
        &self,
        user_id: &UserId,
    ) -> impl Future<Output = Result<Option<BehaviorProfile>, String>> + Send;

    fn save_profile(
        &self,
        user_id: &UserId,
        profile: &BehaviorProfile,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

pub trait AuditRepository: Send + Sync {
    fn record_decision(
        &self,
        entry: &AuditEntry,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

pub struct PostgresStorage {
    pool: sqlx::PgPool,
}

impl PostgresStorage {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}
