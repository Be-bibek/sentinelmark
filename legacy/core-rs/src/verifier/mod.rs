//! # `verifier` — Constant-Time Watermark and Chain Verifier
//!
//! Phase 1 stub — full implementation in Phase 2.
//!
//! The verifier will:
//! - Recompute `W_i` given `K_static`, `BehaviorFingerprint_i`, `H_prev`, `nonce`
//! - Compare recomputed vs stored watermark using `subtle::ConstantTimeEq`
//! - Verify chain linkage via `ChainManager::verify_chain`
//! - Detect replay via nonce deduplication (BloomFilter + persistent set)
//! - Detect timestamp anomalies (±30s clock skew tolerance)
//! - Return a structured `VerificationResult` with trust score

pub mod replay;

use crate::crypto::ct_bytes_eq;
use crate::telemetry::TelemetryEvent;
use crate::watermark::{WatermarkEngine, WatermarkOutput};
use crate::behavior::BehaviorDigest;
use self::replay::ReplayDetector;

/// Result of watermark verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the watermark is cryptographically valid.
    pub watermark_valid: bool,
    /// Whether the chain linkage is intact.
    pub chain_valid: bool,
    /// Whether a replay was detected.
    pub replay_detected: bool,
    /// Composite trust score in [0.0, 1.0].
    pub trust_score: f64,
}

/// Phase 1 & 2: Watermark verifier and replay detection state.
pub struct Verifier {
    engine: WatermarkEngine,
    replay_detector: ReplayDetector,
}

impl Verifier {
    /// Construct with the same `StaticKey` used by the emitting engine.
    /// Also instantiates a default `ReplayDetector`.
    pub fn new(engine: WatermarkEngine) -> Self {
        Self { 
            engine,
            replay_detector: ReplayDetector::default(),
        }
    }

    /// Expose the replay detector for telemetry event checks.
    pub fn replay_detector(&self) -> &ReplayDetector {
        &self.replay_detector
    }

    /// Verify that an event's stored watermark matches a recomputed one.
    ///
    /// # Parameters
    /// - `event`    — The telemetry event to verify
    /// - `behavior` — The `BehaviorFingerprint_i` claimed at event time
    ///
    /// Uses constant-time comparison — does NOT short-circuit on mismatch.
    pub fn verify_watermark(
        &self,
        event: &TelemetryEvent,
        behavior: &BehaviorDigest,
    ) -> Result<bool, crate::watermark::WatermarkError> {
        let expected: WatermarkOutput =
            self.engine.derive(behavior, &event.prev_hash, &event.nonce)?;

        Ok(ct_bytes_eq(event.watermark.as_ref(), expected.as_ref()))
    }
}
