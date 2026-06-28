//! Configurable authentication middleware.
//! AUTH_MODE=disabled (default) | jwt | apikey | oauth

use axum::{extract::{Request, State}, middleware::Next, response::Response};
use crate::{config::AuthMode, state::AppState, error::AppError};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    match state.config.auth_mode {
        AuthMode::Disabled => Ok(next.run(request).await),
        AuthMode::Jwt => {
            let secret = state.config.jwt_secret.as_deref().unwrap_or("");
            let token = extract_bearer(request.headers())
                .ok_or(AppError::Unauthorized)?;

            decode::<Claims>(
                token,
                &DecodingKey::from_secret(secret.as_bytes()),
                &Validation::new(Algorithm::HS256),
            )
            .map_err(|_| AppError::Unauthorized)?;

            Ok(next.run(request).await)
        }
        AuthMode::ApiKey => {
            // Extension point — implement when API key mode is needed
            Ok(next.run(request).await)
        }
    }
}

fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    let value = headers.get("Authorization")?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}
