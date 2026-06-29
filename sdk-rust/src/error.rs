use thiserror::Error;

#[derive(Error, Debug)]
pub enum SentinelMarkError {
    #[error("Authentication Error [{error_code}]: {message} (Request ID: {request_id})")]
    Auth {
        error_code: String,
        message: String,
        request_id: String,
    },
    #[error("Validation Error [{error_code}]: {message} (Request ID: {request_id})")]
    Validation {
        error_code: String,
        message: String,
        request_id: String,
    },
    #[error("Rate Limit Error [{error_code}]: {message} (Request ID: {request_id})")]
    RateLimit {
        error_code: String,
        message: String,
        request_id: String,
    },
    #[error("API Error [{error_code}]: {message} (Request ID: {request_id})")]
    Api {
        error_code: String,
        message: String,
        request_id: String,
    },
    #[error("Network Error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Parse Error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("Unknown Error: {0}")]
    Unknown(String),
}
