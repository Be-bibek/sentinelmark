use chrono::{DateTime, Utc};
use policy_engine::PolicyDecision;
use sentinelmark_core::UserId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub user_id: UserId,
    pub trust_score: f64,
    pub decision: PolicyDecision,
    pub reasons: Vec<String>,
}
