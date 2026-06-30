use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use utoipa::ToSchema;

/// The unified event envelope sent by all SDKs
#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub struct EventIngestRequest {
    pub product_slug: String,
    pub api_version: String,
    pub protocol_version: String,
    pub sdk_version: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// The decision produced by the Trust Engine pipeline
#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct ActionPolicy {
    pub action: String, // "ALLOW", "BLOCK", "MFA"
    pub risk_score: f64,
    pub trust_score: f64,
    pub message: String,
}

// ─── Domain Specific Payloads ───────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub struct DicomTracePayload {
    pub modality: String,
    pub z_score: f64,
    pub entropy_collapse: bool,
    pub affected_instance_uid: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub struct ProofTrace5GPayload {
    pub gnode_b_id: String,
    pub slice_id: String,
    pub sequence_gap: u64,
    pub bit_flip_detected: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub struct StellarFlowPayload {
    pub contract_address: String,
    pub transfer_amount_wei: String,
    pub multisig_threshold_met: bool,
    pub destination_wallet: String,
}
