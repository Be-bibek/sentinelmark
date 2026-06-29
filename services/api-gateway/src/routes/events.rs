use axum::{Extension, extract::State, Json, http::StatusCode, response::IntoResponse};
use serde_json::json;
use uuid::Uuid;

use crate::{
    adapters::models::EventIngestRequest,
    middleware::auth::AuthContext,
    state::AppState,
};

pub async fn handle_platform_event(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<AuthContext>,
    Json(req): Json<EventIngestRequest>,
) -> impl IntoResponse {
    // 1. Validate Project Product registry
    let is_active_query: Result<Option<(bool, String)>, _> = sqlx::query_as(
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
    .await;

    let (_is_enabled, category) = match is_active_query {
        Ok(Some((enabled, category))) => {
            if !enabled {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "This product module is disabled for your project." })),
                ).into_response();
            }
            (enabled, category)
        },
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "This product module is not mapped to your project." })),
            ).into_response();
        },
        Err(e) => {
            tracing::error!("DB Error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database error validating product registry." })),
            ).into_response();
        }
    };

    // 2. Fetch the corresponding ProductAdapter
    let adapter = match state.registry.get_adapter(&req.product_slug) {
        Some(a) => a,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Unsupported product slug: '{}'", req.product_slug) })),
        ).into_response(),
    };

    // 3. Delegate validation and analysis to the adapter
    if let Err(e) = adapter.validate(&req.payload) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e })),
        ).into_response();
    }

    let analysis = match adapter.analyze(&req.payload) {
        Ok(a) => a,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e })),
        ).into_response(),
    };

    // 4. Context Engine evaluates the analysis to produce an Action Policy
    let policy = crate::adapters::ContextEngine::evaluate(&category, analysis);

    // 5. Commit to the immutable centralized telemetry ledger
    let event_id = Uuid::new_v4();
    // Defaulting severity to INFO, could be extended later
    let severity = "INFO"; 
    
    let insert_res = sqlx::query(
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
    .await;

    if let Err(e) = insert_res {
        tracing::error!("DB Insert Error: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Data platform failure committing security event." })),
        ).into_response();
    }

    // 6. Return evaluation instructions back to the Spoke SDK
    (
        StatusCode::OK,
        Json(json!({
            "event_id": event_id,
            "decision": policy.action,
            "risk_score": policy.risk_score,
            "trust_score": policy.trust_score,
            "message": policy.message
        })),
    ).into_response()
}
