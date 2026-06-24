//! SentinelMark v2 — API Gateway
//!
//! Axum-based REST gateway. This service is a deployment wrapper around
//! the sentinelmark-rs SDK. All business logic lives in the SDK.
//!
//! Endpoints:
//!   GET  /health                   — liveness probe
//!   POST /evaluate                 — evaluate a telemetry event
//!   POST /telemetry                — ingest raw telemetry
//!   GET  /behavior-profile/:uid    — retrieve behavior profile (stub)
//!   GET  /audit/:uid               — retrieve audit log (stub)

use axum::{
    routing::{get, post},
    Router, Json,
    http::StatusCode,
    extract::{State, Path},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

use sentinelmark_rs::{SentinelMark, EvaluationResult};
use telemetry_engine::TelemetryEvent;
use behavior_engine::BehaviorProfile;

#[derive(Clone)]
struct AppState {
    engine: Arc<SentinelMark>,
}

#[derive(Deserialize)]
struct EvaluateRequest {
    event: TelemetryEvent,
    profile: BehaviorProfile,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok", version: "2.0.0" })
}

async fn evaluate(
    State(state): State<AppState>,
    Json(payload): Json<EvaluateRequest>,
) -> Result<Json<EvaluationResult>, StatusCode> {
    info!(user_id = ?payload.event.user_id, "Evaluating trust for event");
    let result = state.engine.evaluate(&payload.event, &payload.profile);
    Ok(Json(result))
}

async fn get_telemetry() -> StatusCode {
    // TODO: Persist telemetry event to storage-engine
    StatusCode::ACCEPTED
}

async fn get_behavior_profile(Path(user_id): Path<String>) -> Json<serde_json::Value> {
    info!(user_id = %user_id, "Fetching behavior profile");
    // TODO: Wire to storage-engine ProfileRepository
    Json(serde_json::json!({ "user_id": user_id, "status": "stub" }))
}

async fn get_audit(Path(user_id): Path<String>) -> Json<serde_json::Value> {
    info!(user_id = %user_id, "Fetching audit log");
    // TODO: Wire to storage-engine AuditRepository
    Json(serde_json::json!({ "user_id": user_id, "entries": [] }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = AppState {
        engine: Arc::new(SentinelMark::new()),
    };

    let app = Router::new()
        .route("/health",                    get(health))
        .route("/evaluate",                  post(evaluate))
        .route("/telemetry",                 post(get_telemetry))
        .route("/behavior-profile/:user_id", get(get_behavior_profile))
        .route("/audit/:user_id",            get(get_audit))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("SentinelMark v2 API Gateway listening on :3000");
    axum::serve(listener, app).await.unwrap();
}
