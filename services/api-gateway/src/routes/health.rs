//! Health endpoints: /api/v1/health/live and /api/v1/health/ready

use axum::{extract::State, Json};
use serde::Serialize;
use chrono::Utc;
use crate::state::AppState;

#[derive(Serialize)]
pub struct LivenessResponse {
    pub status: &'static str,
    pub timestamp: String,
}

#[derive(Serialize)]
pub struct ReadinessResponse {
    pub status: &'static str,
    pub database: &'static str,
    pub websocket: &'static str,
    pub timestamp: String,
}

pub async fn health_live() -> Json<LivenessResponse> {
    Json(LivenessResponse {
        status: "ok",
        timestamp: Utc::now().to_rfc3339(),
    })
}

pub async fn health_ready(State(state): State<AppState>) -> Json<ReadinessResponse> {
    let db_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    let db_status = if db_ok { "ok" } else { "degraded" };
    let overall = if db_ok { "ready" } else { "degraded" };

    Json(ReadinessResponse {
        status: overall,
        database: db_status,
        websocket: "ok",
        timestamp: Utc::now().to_rfc3339(),
    })
}
