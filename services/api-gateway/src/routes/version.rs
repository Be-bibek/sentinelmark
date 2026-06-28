//! GET /api/v1/version

use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct VersionResponse {
    pub service: &'static str,
    pub version: &'static str,
    pub sdk_version: &'static str,
    pub api: &'static str,
}

pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        service: "SentinelMark",
        version: "2.0.0",
        sdk_version: "2.0.0",
        api: "v1",
    })
}
