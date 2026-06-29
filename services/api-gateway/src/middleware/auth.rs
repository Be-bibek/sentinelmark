//! API Key Authentication Middleware
//!
//! Supports two modes via AUTH_MODE env var:
//!   - "disabled" → pass-through (development)
//!   - "apikey"   → full validation pipeline (production)
//!   - "jwt"      → JWT validation
//!
//! Full API key pipeline:
//!   Extract Bearer token → SHA-256 hash → DB lookup
//!   → key active? → project active? → tenant active?
//!   → inject AuthContext into request extensions
//!   → fire-and-forget: update last_used_at

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{config::AuthMode, error::AppError, state::AppState};

/// Resolved tenant/project context injected into every authenticated request's extensions.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub tenant_id:  Uuid,
    pub project_id: Uuid,
    pub api_key_id: Uuid,
    pub key_prefix: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

// ─── Helper responses ─────────────────────────────────────────────────────────

fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "Unauthorized", "message": msg })),
    )
        .into_response()
}

fn forbidden(msg: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "error": "Forbidden", "message": msg })),
    )
        .into_response()
}

// ─── Bearer extraction ────────────────────────────────────────────────────────

fn extract_bearer_str(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
}

fn extract_bearer<'a>(headers: &'a axum::http::HeaderMap) -> Option<&'a str> {
    let value = headers.get("Authorization")?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

/// SHA-256 hex digest of the raw API key.
fn hash_key(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ─── Main middleware ──────────────────────────────────────────────────────────

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    match state.config.auth_mode {
        // ── Development / disabled mode ──────────────────────────────────────
        AuthMode::Disabled => Ok(next.run(request).await),

        // ── JWT mode ─────────────────────────────────────────────────────────
        AuthMode::Jwt => {
            let secret = state.config.jwt_secret.as_deref().unwrap_or("");
            let token = extract_bearer(request.headers()).ok_or(AppError::Unauthorized)?;
            decode::<Claims>(
                token,
                &DecodingKey::from_secret(secret.as_bytes()),
                &Validation::new(Algorithm::HS256),
            )
            .map_err(|_| AppError::Unauthorized)?;
            Ok(next.run(request).await)
        }

        // ── API Key mode (production) ─────────────────────────────────────────
        AuthMode::ApiKey => {
            // 1. Extract Bearer token
            let raw_key = match extract_bearer_str(request.headers()) {
                Some(k) => k,
                None => {
                    return Ok(unauthorized(
                        "Missing Authorization header. Expected: Bearer sm_live_...",
                    ))
                }
            };

            // 2. Hash and look up in database
            let key_hash = hash_key(&raw_key);

            let row: Option<(Uuid, Uuid, bool, String)> = sqlx::query_as(
                r#"SELECT k.id, k.project_id, k.is_active, k.key_prefix
                   FROM api_keys k
                   WHERE k.key_hash = $1
                   LIMIT 1"#,
            )
            .bind(&key_hash)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

            let (api_key_id, project_id, is_key_active, key_prefix) = match row {
                Some(r) => r,
                None => return Ok(unauthorized("Invalid API key")),
            };

            // 3. Check key is active
            if !is_key_active {
                return Ok(forbidden("API key has been revoked"));
            }

            // 4. Check project and tenant status
            let project_row: Option<(Uuid, String, String)> = sqlx::query_as(
                r#"SELECT p.tenant_id, p.status, t.status
                   FROM projects p
                   JOIN tenants t ON t.id = p.tenant_id
                   WHERE p.id = $1
                   LIMIT 1"#,
            )
            .bind(project_id)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

            let (tenant_id, project_status, tenant_status) = match project_row {
                Some(r) => r,
                None => return Ok(forbidden("Project not found")),
            };

            if project_status != "active" {
                return Ok(forbidden("Project is suspended"));
            }
            if tenant_status != "active" {
                return Ok(forbidden("Tenant account is suspended"));
            }

            // 5. Inject AuthContext into request extensions
            request.extensions_mut().insert(AuthContext {
                tenant_id,
                project_id,
                api_key_id,
                key_prefix,
            });

            // 6. Fire-and-forget: update last_used_at (non-blocking)
            let pool = state.db.clone();
            let kid = api_key_id;
            tokio::spawn(async move {
                let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
                    .bind(kid)
                    .execute(&pool)
                    .await;
            });

            // 7. Continue
            Ok(next.run(request).await)
        }
    }
}
