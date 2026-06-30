use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use serde_json::json;

use crate::{middleware::auth::AuthContext, state::AppState};

pub async fn get_tenant(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<AuthContext>,
) -> impl IntoResponse {
    let record: Result<Option<(uuid::Uuid, String, String, chrono::DateTime<chrono::Utc>)>, _> =
        sqlx::query_as(
            r#"
        SELECT id, name, status, created_at
        FROM tenants
        WHERE id = $1
        "#,
        )
        .bind(auth_ctx.tenant_id)
        .fetch_optional(&state.db)
        .await;

    match record {
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(json!({
                "organization": {
                    "id": row.0,
                    "name": row.1,
                    "status": row.2,
                    "created_at": row.3
                }
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Organization not found" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("DB Error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database error" })),
            )
                .into_response()
        }
    }
}
