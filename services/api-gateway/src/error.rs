//! Unified application error type.
//! Every error maps to a consistent JSON response with code, message, and request_id.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use uuid::Uuid;
use chrono::Utc;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error("Profile not found for user: {0}")]
    ProfileNotFound(String),
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Authentication required")]
    Unauthorized,
    #[error("Internal server error")]
    Internal(String),
    #[error("Not found")]
    NotFound(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
}

#[derive(Serialize)]
struct ErrorBody {
    code: String,
    message: String,
    request_id: String,
    timestamp: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: ErrorBody,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::ProfileNotFound(u) => (
                StatusCode::NOT_FOUND,
                "PROFILE_NOT_FOUND",
                format!("Profile not found for user: {u}"),
            ),
            AppError::UserNotFound(u) => (
                StatusCode::NOT_FOUND,
                "USER_NOT_FOUND",
                format!("User not found: {u}"),
            ),
            AppError::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                msg.clone(),
            ),
            AppError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "A database error occurred.".to_string(),
            ),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Authentication required.".to_string(),
            ),
            AppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "An internal error occurred.".to_string(),
            ),
            AppError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                msg.clone(),
            ),
            AppError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                msg.clone(),
            ),
        };

        let body = ErrorResponse {
            success: false,
            error: ErrorBody {
                code: code.to_string(),
                message,
                request_id: Uuid::new_v4().to_string(),
                timestamp: Utc::now().to_rfc3339(),
            },
        };

        (status, Json(body)).into_response()
    }
}

impl From<storage_engine::StorageError> for AppError {
    fn from(e: storage_engine::StorageError) -> Self {
        match e {
            storage_engine::StorageError::UserNotFound(u) => AppError::UserNotFound(u),
            _ => AppError::Database(e.to_string()),
        }
    }
}
