//! Core primitives shared across the entire SentinelMark v2 platform.
//! All types here are pure data structures — no I/O, no networking.

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("Evaluation failed: {0}")]
    EvaluationError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Identity error: {0}")]
    IdentityError(String),
}

/// Newtype wrapper ensuring user IDs are strongly typed throughout the codebase.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct UserId(pub String);

/// Newtype wrapper ensuring device IDs are strongly typed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DeviceId(pub String);

/// A single human-readable explanation for one trust factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorExplanation {
    pub factor: String,
    pub detail: String,
    pub weight: f64,
}
