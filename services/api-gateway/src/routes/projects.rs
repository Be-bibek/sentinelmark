use axum::{Extension, extract::State, Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

use crate::{
    middleware::auth::AuthContext,
    state::AppState,
};

pub async fn get_project(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<AuthContext>,
) -> impl IntoResponse {
    let record: Result<Option<(
        uuid::Uuid,
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>
    )>, _> = sqlx::query_as(
        r#"
        SELECT id, name, environment, status, created_at
        FROM projects
        WHERE id = $1 AND tenant_id = $2
        "#
    )
    .bind(auth_ctx.project_id)
    .bind(auth_ctx.tenant_id)
    .fetch_optional(&state.db)
    .await;

    match record {
        Ok(Some(row)) => {
            (StatusCode::OK, Json(json!({ 
                "project": {
                    "id": row.0,
                    "name": row.1,
                    "environment": row.2,
                    "status": row.3,
                    "created_at": row.4
                }
            }))).into_response()
        },
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Project not found" }))).into_response(),
        Err(e) => {
            tracing::error!("DB Error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Database error" }))).into_response()
        }
    }
}
