//! Standard API response envelope.
//! Every successful endpoint returns the same structure.

use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde::Serialize;
use chrono::Utc;

#[derive(Debug, Serialize)]
pub struct Meta {
    pub request_id: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation_time_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: T,
    pub meta: Meta,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T, request_id: String) -> Self {
        Self::ok_with_latency(data, request_id, None)
    }

    pub fn ok_with_latency(data: T, request_id: String, eval_ms: Option<i64>) -> Self {
        ApiResponse {
            success: true,
            data,
            meta: Meta {
                request_id,
                timestamp: Utc::now().to_rfc3339(),
                evaluation_time_ms: eval_ms,
            },
        }
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
