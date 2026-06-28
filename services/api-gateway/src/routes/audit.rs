//! GET /api/v1/audit/:user_id — Paginated audit log (newest first).

use axum::{
    extract::{State, Path, Query},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{error::AppError, response::ApiResponse, state::AppState};
use sentinelmark_core::UserId;
use storage_engine::{AuditRepository, AuditRow};

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Serialize)]
pub struct AuditListResponse {
    pub user_id: String,
    pub entries: Vec<AuditRow>,
    pub page: i64,
    pub per_page: i64,
    pub total_returned: usize,
}

pub async fn get_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<ApiResponse<AuditListResponse>, AppError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * per_page;

    let uid = UserId(user_id.clone());
    let entries = state
        .storage
        .list_for_user(&uid, per_page, offset)
        .await?;

    let total = entries.len();
    info!(user_id = %user_id, count = total, page = page, "Audit log fetched");

    Ok(ApiResponse::ok(
        AuditListResponse {
            user_id,
            entries,
            page,
            per_page,
            total_returned: total,
        },
        request_id,
    ))
}
