//! # SentinelMark Core — `sentinelmark_core`
//!
//! Implements **Behavior-Entangled Watermarking (BEW)**: a cryptographic trust
//! primitive that binds tamper-evident forensic watermarks to the *live behavioral
//! state* of the issuing device.
//!
//! ## Derivation Equation
//!
//! ```text
//! W_i = HKDF-SHA256(
//!     IKM  = K_static || BehaviorFingerprint_i || H_prev,
//!     salt = nonce_i,
//!     info = b"sentinelmark-bew-v1"
//! )
//! ```
//!
//! - `K_static`             — long-term device secret (never leaves device)
//! - `BehaviorFingerprint_i`— rolling entropy snapshot (CPU, memory, threads, jitter)
//! - `H_prev`               — previous chain hash (links events into a Merkle-like chain)
//!
//! ## Security Properties
//!
//! | Property | Mechanism |
//! |---|---|
//! | Replay resistance | per-event random nonce + timestamp window |
//! | Forge resistance | HKDF keyed with device secret |
//! | Behavioral binding | BehaviorFingerprint included in IKM |
//! | Chain integrity | H_prev chaining; any gap breaks verification |
//! | Secret erasure | `zeroize` on all key material |
//! | Timing safety | `subtle::ConstantTimeEq` on all comparisons |
//!
//! ## Module Map
//!
//! ```text
//! sentinelmark_core
//! +-- behavior  -- behavioral fingerprint capture (CPU, memory, jitter)
//! +-- crypto    -- low-level primitives (HKDF, SHA-256, constant-time)
//! +-- watermark -- BEW derivation engine
//! +-- chain     -- event chain manager and integrity verifier
//! +-- telemetry -- event schema + deterministic serialization
//! +-- verifier  -- watermark + chain verification logic
//! +-- transport -- async event dispatch (reqwest + tokio)
//! ```

#![deny(unsafe_code)]               // no unsafe unless explicitly gated
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

// ─── Public Modules ─────────────────────────────────────────────────────────

/// Behavioral entropy capture: CPU, memory, thread count, timing jitter.
pub mod behavior;

/// Low-level cryptographic primitives: HKDF-SHA256, SHA-256, constant-time ops.
pub mod crypto;

/// Behavior-Entangled Watermark (BEW) derivation engine.
pub mod watermark;

/// Event hash chain: append, verify, and detect gaps.
pub mod chain;

/// Telemetry event schema and deterministic serialization.
pub mod telemetry;

/// Watermark and chain verification (constant-time, replay-aware).
pub mod verifier;

/// Async transport layer for telemetry emission.
pub mod transport;

// ─── Crate-level Re-exports ──────────────────────────────────────────────────

pub use watermark::WatermarkEngine;
pub use chain::ChainManager;
pub use telemetry::{TelemetryEvent, EventId};
pub use verifier::Verifier;
pub use behavior::BehaviorSampler;

// ─── Error type ─────────────────────────────────────────────────────────────

/// Top-level error type for the sentinelmark_core crate.
#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    /// Watermark derivation failed.
    #[error("watermark derivation failed: {0}")]
    Watermark(String),

    /// Chain integrity violation.
    #[error("chain integrity violation: {0}")]
    ChainIntegrity(String),

    /// Replay attack detected.
    #[error("replay detected: {0}")]
    ReplayDetected(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Behavioral sampling error.
    #[error("behavior sampling error: {0}")]
    BehaviorSampling(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, SentinelError>;
