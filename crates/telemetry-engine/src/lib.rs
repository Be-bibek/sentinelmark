use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use sentinelmark_core::{UserId, DeviceId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    Login,
    Logout,
    SessionPing,
    Transaction,
    Approval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub user_id: UserId,
    pub timestamp: DateTime<Utc>,
    pub device_id: DeviceId,
    pub browser_fingerprint: String,
    pub ip_address: String,
    pub geo_region: String,
    pub action_type: ActionType,
    pub transaction_amount: Option<f64>,
    pub session_duration_secs: Option<u64>,
}
