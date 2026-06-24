//! SentinelMark SDK
//!
//! The primary developer-facing interface for SentinelMark v2.
//! Hides all internal engine complexity behind a single evaluation call.
//!
//! # Example
//! ```rust
//! let engine = SentinelMark::new();
//! let result = engine.evaluate(&event, &profile);
//! println!("{:?}", result.decision);
//! ```

use serde::{Deserialize, Serialize};
use telemetry_engine::TelemetryEvent;
use behavior_engine::{BehaviorEngine, BehaviorProfile};
use risk_engine::RiskEngine;
use trust_engine::TrustEngine;
use policy_engine::{PolicyEngine, PolicyDecision};

/// The complete output from a single trust evaluation.
#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub risk_score: f64,
    pub trust_score: f64,
    pub decision: PolicyDecision,
    pub requires_multi_sig: bool,
    pub reasons: Vec<String>,
    pub explanation: String,
}

/// Top-level SentinelMark engine.
///
/// Blockchain-agnostic. StellarFlow, Ethereum, Solana, and other systems
/// should consume SentinelMark through this SDK or the REST API.
/// Trust infrastructure is the product; blockchain is only an example consumer.
pub struct SentinelMark;

impl SentinelMark {
    pub fn new() -> Self {
        Self
    }

    /// Evaluate a telemetry event against the user's behavior profile.
    ///
    /// All computation is pure and deterministic. No I/O is performed.
    pub fn evaluate(&self, event: &TelemetryEvent, profile: &BehaviorProfile) -> EvaluationResult {
        let deviation  = BehaviorEngine::detect_deviations(profile, event);
        let risk       = RiskEngine::assess(&deviation);
        let trust      = TrustEngine::evaluate(&risk);
        let policy     = PolicyEngine::enforce(&trust);

        EvaluationResult {
            risk_score: risk.score,
            trust_score: trust.score,
            decision: policy.decision,
            requires_multi_sig: policy.requires_multi_sig,
            reasons: risk.factors,
            explanation: risk.explanation,
        }
    }
}

impl Default for SentinelMark {
    fn default() -> Self {
        Self::new()
    }
}
