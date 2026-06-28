//! GET /api/v1/behavior-profile/:user_id — Returns full behavior profile from PostgreSQL.

use axum::{extract::{State, Path}, http::HeaderMap};
use serde::Serialize;
use tracing::info;

use crate::{error::AppError, response::ApiResponse, state::AppState};
use sentinelmark_core::UserId;
use storage_engine::ProfileRepository;

#[derive(Serialize)]
pub struct BehaviorProfileResponse {
    pub user_id: String,
    pub known_devices: Vec<String>,
    pub known_regions: Vec<String>,
    pub avg_transaction_amount: f64,
}

pub async fn get_behavior_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<ApiResponse<BehaviorProfileResponse>, AppError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let uid = UserId(user_id.clone());
    let profile = state
        .storage
        .get_profile(&uid)
        .await?
        .ok_or_else(|| AppError::ProfileNotFound(user_id.clone()))?;

    info!(user_id = %user_id, "Behavior profile fetched");

    Ok(ApiResponse::ok(
        BehaviorProfileResponse {
            user_id,
            known_devices: profile.known_devices.into_iter().collect(),
            known_regions: profile.known_regions.into_iter().collect(),
            avg_transaction_amount: profile.avg_transaction_amount,
        },
        request_id,
    ))
}
