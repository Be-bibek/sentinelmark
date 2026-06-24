use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use sentinelmark_core::UserId;
use policy_engine::PolicyDecision;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub user_id: UserId,
    pub trust_score: f64,
    pub decision: PolicyDecision,
    pub reasons: Vec<String>,
}
