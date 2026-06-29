use axum::{Extension, extract::State, Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

use crate::{
    middleware::auth::AuthContext,
    state::AppState,
};

pub async fn list_events(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<AuthContext>,
) -> impl IntoResponse {
    let records: Result<Vec<(
        uuid::Uuid,
        String,
        String,
        String,
        f64,
        f64,
        String,
        chrono::DateTime<chrono::Utc>
    )>, _> = sqlx::query_as(
        r#"
        SELECT id, product_slug, event_type, severity, risk_score, trust_score, action_taken, timestamp
        FROM trust_events
        WHERE project_id = $1
        ORDER BY timestamp DESC
        LIMIT 100
        "#
    )
    .bind(auth_ctx.project_id)
    .fetch_all(&state.db)
    .await;

    match records {
        Ok(rows) => {
            let events: Vec<_> = rows.into_iter().map(|r| json!({
                "id": r.0,
                "product_slug": r.1,
                "event_type": r.2,
                "severity": r.3,
                "risk_score": r.4,
                "trust_score": r.5,
                "action_taken": r.6,
                "timestamp": r.7
            })).collect();
            (StatusCode::OK, Json(json!({ "events": events }))).into_response()
        },
        Err(e) => {
            tracing::error!("DB Error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Database error" }))).into_response()
        }
    }
}
