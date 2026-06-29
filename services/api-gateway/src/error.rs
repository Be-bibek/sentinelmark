use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use utoipa::ToSchema;

#[derive(Debug, thiserror::Error)]
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

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("Invalid API Key")]
    InvalidApiKey,
    #[error("Project Suspended")]
    ProjectSuspended,
    #[error("Tenant Suspended")]
    TenantSuspended,
    #[error("Payload Invalid: {0}")]
    PayloadInvalid(String),
    #[error("Trust Engine Failure: {0}")]
    TrustEngineFailure(String),
    #[error("Unsupported SDK Version")]
    UnsupportedSdkVersion,
    #[error("Database Error: {0}")]
    DatabaseError(String),
    #[error("Product Disabled")]
    ProductDisabled,
    #[error("Product Not Mapped")]
    ProductNotMapped,
    #[error("Unsupported Product: {0}")]
    UnsupportedProduct(String),
    #[error("Rate Limit Exceeded")]
    RateLimitExceeded,
    #[error("Internal Server Error")]
    InternalError,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PlatformErrorResponse {
    pub success: bool,
    pub error_code: String,
    pub message: String,
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::ProfileNotFound(u) => (StatusCode::NOT_FOUND, "SM9001", format!("Profile not found for user: {u}")),
            AppError::UserNotFound(u) => (StatusCode::NOT_FOUND, "SM9002", format!("User not found: {u}")),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, "SM2001", msg.clone()),
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "SM5001", "A database error occurred.".to_string()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "SM1001", "Authentication required.".to_string()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "SM8001", "An internal error occurred.".to_string()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "SM9003", msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "SM2002", msg.clone()),
        };

        let body = PlatformErrorResponse {
            success: false,
            error_code: code.to_string(),
            message,
            request_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
        };

        (status, Json(body)).into_response()
    }
}

impl IntoResponse for PlatformError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            PlatformError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "SM1001", self.to_string()),
            PlatformError::ProjectSuspended => (StatusCode::FORBIDDEN, "SM1101", self.to_string()),
            PlatformError::TenantSuspended => (StatusCode::FORBIDDEN, "SM1102", self.to_string()),
            PlatformError::PayloadInvalid(m) => (StatusCode::BAD_REQUEST, "SM2001", m.clone()),
            PlatformError::TrustEngineFailure(m) => (StatusCode::INTERNAL_SERVER_ERROR, "SM3001", m.clone()),
            PlatformError::UnsupportedSdkVersion => (StatusCode::BAD_REQUEST, "SM4001", self.to_string()),
            PlatformError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "SM5001", "A database error occurred".to_string()),
            PlatformError::ProductDisabled => (StatusCode::FORBIDDEN, "SM6001", self.to_string()),
            PlatformError::ProductNotMapped => (StatusCode::FORBIDDEN, "SM6002", self.to_string()),
            PlatformError::UnsupportedProduct(m) => (StatusCode::BAD_REQUEST, "SM6003", format!("Unsupported Product: {}", m)),
            PlatformError::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, "SM7001", self.to_string()),
            PlatformError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "SM8001", self.to_string()),
        };

        let body = PlatformErrorResponse {
            success: false,
            error_code: error_code.to_string(),
            message,
            request_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
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
