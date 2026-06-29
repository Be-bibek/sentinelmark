use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub engine_version: String,
    pub api_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<i64>,
    pub data: T,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn new(data: T, request_id: String) -> Self {
        Self {
            success: true,
            request_id,
            timestamp: Utc::now(),
            engine_version: "2.3.0".to_string(), // Fetched from env in production
            api_version: "v1".to_string(),
            latency_ms: None,
            data,
        }
    }

    pub fn ok(data: T, request_id: String) -> Self {
        Self::new(data, request_id)
    }

    pub fn ok_with_latency(data: T, request_id: String, eval_ms: Option<i64>) -> Self {
        Self {
            success: true,
            request_id,
            timestamp: Utc::now(),
            engine_version: "2.3.0".to_string(),
            api_version: "v1".to_string(),
            latency_ms: eval_ms,
            data,
        }
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
