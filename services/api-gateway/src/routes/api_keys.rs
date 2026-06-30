use axum::{
    extract::Path, extract::State, http::StatusCode, response::IntoResponse, Extension, Json,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{middleware::auth::AuthContext, state::AppState};

// GET /api/v1/api-keys
pub async fn list_keys(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<AuthContext>,
) -> impl IntoResponse {
    let keys: Result<Vec<(
        uuid::Uuid, String, String, bool, i32, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>, Option<i64>
    )>, _> = sqlx::query_as(
        r#"
        SELECT k.id, k.name, k.key_prefix, k.is_active, k.rate_limit_rpm, k.last_used_at, k.created_at,
               (SELECT COUNT(*) FROM usage_records u WHERE u.api_key_id = k.id) as usage_count
        FROM api_keys k
        WHERE k.project_id = $1
        ORDER BY k.created_at DESC
        "#
    )
    .bind(auth_ctx.project_id)
    .fetch_all(&state.db)
    .await;

    match keys {
        Ok(records) => {
            let json_records: Vec<_> = records
                .iter()
                .map(|r| {
                    json!({
                        "id": r.0,
                        "name": r.1,
                        "key_prefix": r.2,
                        "is_active": r.3,
                        "rate_limit_rpm": r.4,
                        "last_used_at": r.5,
                        "created_at": r.6,
                        "usage_count": r.7.unwrap_or(0)
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "api_keys": json_records }))).into_response()
        }
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

// POST /api/v1/api-keys
#[derive(serde::Deserialize)]
pub struct CreateKeyReq {
    pub name: String,
}

pub async fn create_key(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<AuthContext>,
    Json(req): Json<CreateKeyReq>,
) -> impl IntoResponse {
    // Generate raw key: sm_live_ + 32 random chars (from uuid)
    let random_str = Uuid::new_v4().to_string().replace("-", "");
    let raw_key = format!("sm_live_{}", random_str);

    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    let key_hash = format!("{:x}", hasher.finalize());
    let key_prefix = format!("sm_live_{}...", &random_str[0..6]);

    let insert: Result<(uuid::Uuid, chrono::DateTime<chrono::Utc>), _> = sqlx::query_as(
        r#"
        INSERT INTO api_keys (project_id, name, key_hash, key_prefix)
        VALUES ($1, $2, $3, $4)
        RETURNING id, created_at
        "#,
    )
    .bind(auth_ctx.project_id)
    .bind(&req.name)
    .bind(key_hash)
    .bind(&key_prefix)
    .fetch_one(&state.db)
    .await;

    match insert {
        Ok(r) => {
            // ONLY time the raw key is ever returned!
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": r.0,
                    "name": req.name,
                    "raw_key": raw_key,
                    "key_prefix": key_prefix,
                    "created_at": r.1
                })),
            )
                .into_response()
        }
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

// DELETE /api/v1/api-keys/:id
pub async fn revoke_key(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path(key_id): Path<Uuid>,
) -> impl IntoResponse {
    let res =
        sqlx::query("UPDATE api_keys SET is_active = FALSE WHERE id = $1 AND project_id = $2")
            .bind(key_id)
            .bind(auth_ctx.project_id)
            .execute(&state.db)
            .await;

    match res {
        Ok(_) => (StatusCode::OK, Json(json!({ "message": "Key revoked" }))).into_response(),
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
