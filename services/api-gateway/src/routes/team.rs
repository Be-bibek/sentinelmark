use axum::{Extension, extract::State, Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

use crate::{
    middleware::auth::AuthContext,
    state::AppState,
};

pub async fn list_team(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<AuthContext>,
) -> impl IntoResponse {
    let records: Result<Vec<(
        uuid::Uuid, String, String, String, chrono::DateTime<chrono::Utc>
    )>, _> = sqlx::query_as(
        r#"
        SELECT id, name, email, role, created_at
        FROM team_members
        WHERE tenant_id = $1
        "#
    )
    .bind(auth_ctx.tenant_id)
    .fetch_all(&state.db)
    .await;

    match records {
        Ok(rows) => {
            let members: Vec<_> = rows.into_iter().map(|r| json!({
                "id": r.0,
                "name": r.1,
                "email": r.2,
                "role": r.3,
                "created_at": r.4
            })).collect();
            (StatusCode::OK, Json(json!({ "team": members }))).into_response()
        },
        Err(e) => {
            tracing::error!("DB Error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Database error" }))).into_response()
        }
    }
}
