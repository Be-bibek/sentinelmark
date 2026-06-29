use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct EvaluateOptions {
    pub product_slug: String,
    pub event_type: String,
    pub payload: Value,
    pub metadata: Option<Value>,
    #[serde(skip)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InternalEventRequest {
    pub product_slug: String,
    pub api_version: String,
    pub protocol_version: String,
    pub sdk_version: String,
    pub event_type: String,
    pub timestamp: String,
    pub payload: Value,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub request_id: String,
    pub timestamp: String,
    pub engine_version: String,
    pub api_version: String,
    pub latency_ms: Option<i64>,
    pub data: T,
}

#[derive(Debug, Deserialize)]
pub struct EventResponse {
    pub event_id: String,
    pub decision: String,
    pub risk_score: f64,
    pub trust_score: f64,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ErrorBody {
    pub error_code: String,
    pub message: String,
    pub request_id: String,
}
