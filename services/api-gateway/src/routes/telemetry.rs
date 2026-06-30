//! POST /api/v1/telemetry — Ingest and persist raw telemetry events.

use axum::{extract::State, http::HeaderMap, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;
use validator::Validate;

use crate::ws::WsEvent;
use crate::{error::AppError, response::ApiResponse, state::AppState};
use sentinelmark_core::UserId;
use storage_engine::{ProfileRepository, TelemetryRepository, TelemetryRow};

#[derive(Debug, Deserialize, Validate)]
pub struct TelemetryRequest {
    #[validate(length(min = 1))]
    pub user_id: String,
    #[validate(length(min = 1))]
    pub device_id: String,
    pub browser_fingerprint: Option<String>,
    pub ip_address: Option<String>,
    pub geo_region: Option<String>,
    pub action_type: String,
    #[validate(range(min = 0.0))]
    pub transaction_amount: Option<f64>,
    pub session_duration_secs: Option<i64>,
}

#[derive(Serialize)]
pub struct TelemetryAck {
    pub telemetry_id: String,
    pub user_id: String,
    pub accepted: bool,
}

pub async fn ingest_telemetry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TelemetryRequest>,
) -> Result<ApiResponse<TelemetryAck>, AppError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    payload
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let user_id = UserId(payload.user_id.clone());

    // Ensure user exists
    state.storage.ensure_user(&user_id).await?;

    let row = TelemetryRow {
        device_id: payload.device_id.clone(),
        browser_fingerprint: payload.browser_fingerprint.unwrap_or_default(),
        ip_address: payload.ip_address.unwrap_or_default(),
        geo_region: payload.geo_region.unwrap_or_default(),
        action_type: payload.action_type.clone(),
        transaction_amount: payload.transaction_amount,
        session_duration_secs: payload.session_duration_secs,
        recorded_at: Utc::now(),
    };

    let id = state.storage.insert_event(&user_id, &row).await?;

    // Broadcast WS event
    let _ = state.ws_tx.send(WsEvent::TelemetryReceived {
        user_id: payload.user_id.clone(),
        device_id: payload.device_id.clone(),
        action_type: payload.action_type,
        timestamp: Utc::now(),
    });

    info!(user_id = %payload.user_id, telemetry_id = %id, "Telemetry ingested");

    Ok(ApiResponse::ok(
        TelemetryAck {
            telemetry_id: id.to_string(),
            user_id: payload.user_id,
            accepted: true,
        },
        request_id,
    ))
}
