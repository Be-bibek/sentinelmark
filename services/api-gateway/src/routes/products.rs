use axum::{Extension, extract::State, extract::Path, Json, http::StatusCode, response::IntoResponse};
use serde_json::json;
use uuid::Uuid;

use crate::{
    middleware::auth::AuthContext,
    state::AppState,
};

pub async fn list_products(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<AuthContext>,
) -> impl IntoResponse {
    let records: Result<Vec<(
        Uuid, String, String, String, String, Option<bool>
    )>, _> = sqlx::query_as(
        r#"
        SELECT p.id, p.slug, p.name, p.category, p.version, pp.enabled
        FROM products p
        LEFT JOIN project_products pp ON p.id = pp.product_id AND pp.project_id = $1
        "#
    )
    .bind(auth_ctx.project_id)
    .fetch_all(&state.db)
    .await;

    match records {
        Ok(rows) => {
            let products: Vec<_> = rows.into_iter().map(|r| json!({
                "id": r.0,
                "slug": r.1,
                "name": r.2,
                "category": r.3,
                "version": r.4,
                "is_enabled": r.5.unwrap_or(false)
            })).collect();
            (StatusCode::OK, Json(json!({ "products": products }))).into_response()
        },
        Err(e) => {
            tracing::error!("DB Error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Database error" }))).into_response()
        }
    }
}

pub async fn toggle_product(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path(product_slug): Path<String>,
) -> impl IntoResponse {
    // Basic toggle mechanism (upsert into project_products)
    let res = sqlx::query(
        r#"
        INSERT INTO project_products (project_id, product_id, enabled)
        SELECT $1, id, true FROM products WHERE slug = $2
        ON CONFLICT (project_id, product_id) DO UPDATE SET enabled = NOT project_products.enabled
        "#
    )
    .bind(auth_ctx.project_id)
    .bind(product_slug)
    .execute(&state.db)
    .await;

    match res {
        Ok(_) => (StatusCode::OK, Json(json!({ "message": "Product toggled" }))).into_response(),
        Err(e) => {
            tracing::error!("DB Error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Database error" }))).into_response()
        }
    }
}
