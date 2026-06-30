use axum::{extract::State, http::HeaderMap, response::IntoResponse, Extension, Json};
use chrono::{Duration, Utc};
use serde::Serialize;
use serde_json::json;
use std::time::Instant;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    adapters::models::EventIngestRequest, error::PlatformError, middleware::auth::AuthContext,
    response::ApiResponse, state::AppState,
};

#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct EventResponse {
    pub event_id: String,
    pub decision: String,
    pub risk_score: f64,
    pub trust_score: f64,
    pub message: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/events",
    request_body = EventIngestRequest,
    responses(
        (status = 200, description = "Event successfully evaluated", body = ApiResponse<EventResponse>),
        (status = 400, description = "Invalid payload or unsupported product", body = PlatformErrorResponse),
        (status = 401, description = "Invalid API Key", body = PlatformErrorResponse),
        (status = 403, description = "Project suspended or product disabled", body = PlatformErrorResponse),
        (status = 500, description = "Internal Trust Engine Failure", body = PlatformErrorResponse)
    ),
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "Unique key for safe retries"),
        ("X-SentinelMark-SDK" = Option<String>, Header, description = "SDK language (e.g., python)"),
        ("X-SentinelMark-Version" = Option<String>, Header, description = "SDK version (e.g., 1.0.0)")
    ),
    security(
        ("api_key" = [])
    )
)]
pub async fn handle_platform_event(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Json(req): Json<EventIngestRequest>,
) -> Result<axum::response::Response, PlatformError> {
    let start_time = Instant::now();

    // -- Idempotency Handling --
    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(ref key) = idempotency_key {
        let cached_res: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT response_body FROM idempotency_keys WHERE project_id = $1 AND idempotency_key = $2 AND expires_at > NOW()"
        )
        .bind(auth_ctx.project_id)
        .bind(key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| PlatformError::DatabaseError(e.to_string()))?;

        if let Some((body,)) = cached_res {
            return Ok(Json(body).into_response());
        }
    }

    // 1. Validate Project Product registry
    let is_active_query: Option<(bool, String)> = sqlx::query_as(
        r#"
        SELECT pp.enabled, p.category 
        FROM project_products pp
        JOIN products p ON p.id = pp.product_id
        WHERE pp.project_id = $1 AND p.slug = $2
        "#,
    )
    .bind(auth_ctx.project_id)
    .bind(&req.product_slug)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| PlatformError::DatabaseError(e.to_string()))?;

    let (_enabled, category) = match is_active_query {
        Some((enabled, category)) => {
            if !enabled {
                return Err(PlatformError::ProductDisabled);
            }
            (enabled, category)
        }
        None => return Err(PlatformError::ProductNotMapped),
    };

    // 2. Fetch the corresponding ProductAdapter
    let adapter = state
        .registry
        .get_adapter(&req.product_slug)
        .ok_or_else(|| PlatformError::UnsupportedProduct(req.product_slug.clone()))?;

    // 3. Delegate validation and analysis to the adapter
    adapter
        .validate(&req.payload)
        .map_err(PlatformError::PayloadInvalid)?;

    let analysis = adapter
        .analyze(&req.payload)
        .map_err(PlatformError::PayloadInvalid)?;

    // 4. Context Engine evaluates the analysis to produce an Action Policy
    let policy = crate::adapters::ContextEngine::evaluate(&category, analysis);

    // 5. Commit to the immutable centralized telemetry ledger
    let event_id = Uuid::new_v4();
    let severity = "INFO";

    sqlx::query(
        r#"
        INSERT INTO trust_events (
            id, tenant_id, project_id, product_slug, event_type, 
            protocol_version, sdk_version, severity, raw_payload, 
            risk_score, trust_score, action_taken, metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        "#,
    )
    .bind(event_id)
    .bind(auth_ctx.tenant_id)
    .bind(auth_ctx.project_id)
    .bind(&req.product_slug)
    .bind(&req.event_type)
    .bind(&req.protocol_version)
    .bind(&req.sdk_version)
    .bind(severity)
    .bind(&req.payload)
    .bind(policy.risk_score)
    .bind(policy.trust_score)
    .bind(&policy.action)
    .bind(&req.metadata)
    .execute(&state.db)
    .await
    .map_err(|e| PlatformError::DatabaseError(e.to_string()))?;

    // 6. Construct Response
    let event_res = EventResponse {
        event_id: event_id.to_string(),
        decision: policy.action,
        risk_score: policy.risk_score,
        trust_score: policy.trust_score,
        message: policy.message,
    };

    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let latency_ms = start_time.elapsed().as_millis() as i64;

    let api_res = ApiResponse::ok_with_latency(event_res, request_id, Some(latency_ms));
    let response_json = json!(api_res);

    // 7. Store Idempotency Key (Fire and Forget)
    if let Some(key) = idempotency_key {
        let pool = state.db.clone();
        let p_id = auth_ctx.project_id;
        let t_id = auth_ctx.tenant_id;
        let body = response_json.clone();

        tokio::spawn(async move {
            let expires_at = Utc::now() + Duration::hours(24);
            let _ = sqlx::query(
                "INSERT INTO idempotency_keys (idempotency_key, tenant_id, project_id, response_body, response_status, expires_at) VALUES ($1, $2, $3, $4, 200, $5) ON CONFLICT DO NOTHING"
            )
            .bind(key)
            .bind(t_id)
            .bind(p_id)
            .bind(body)
            .bind(expires_at)
            .execute(&pool)
            .await;
        });
    }

    Ok(Json(api_res).into_response())
}
