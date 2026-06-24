//! Policy Engine
//!
//! Threshold-based decision engine. Pure and deterministic.
//! No external calls — inputs in, decisions out.

use serde::{Deserialize, Serialize};
use trust_engine::TrustScore;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    RequireMFA,
    /// Requires human approval via an out-of-band multi-sig escalation flow.
    RequireApproval,
    Block,
}

/// Full policy decision including the decision itself and detailed reasoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub decision: PolicyDecision,
    pub trust_score: f64,
    pub threshold_applied: &'static str,
    pub rationale: String,
    pub requires_multi_sig: bool,
}

pub struct PolicyEngine;

impl PolicyEngine {
    /// Enforce trust thresholds and produce a structured policy result.
    pub fn enforce(trust: &TrustScore) -> PolicyResult {
        let score = trust.score;

        if score > 0.85 {
            PolicyResult {
                decision: PolicyDecision::Allow,
                trust_score: score,
                threshold_applied: "Trust > 0.85",
                rationale: "High trust context established. Behavioral profile matches all baselines.".to_string(),
                requires_multi_sig: false,
            }
        } else if score > 0.65 {
            PolicyResult {
                decision: PolicyDecision::RequireMFA,
                trust_score: score,
                threshold_applied: "Trust 0.65–0.85",
                rationale: "Moderate trust context. Step-up authentication required before sensitive actions.".to_string(),
                requires_multi_sig: false,
            }
        } else if score > 0.45 {
            PolicyResult {
                decision: PolicyDecision::RequireApproval,
                trust_score: score,
                threshold_applied: "Trust 0.45–0.65",
                rationale: "Low trust context. Request escalated to multi-sig approval flow. No automated execution permitted.".to_string(),
                requires_multi_sig: true,
            }
        } else {
            PolicyResult {
                decision: PolicyDecision::Block,
                trust_score: score,
                threshold_applied: "Trust ≤ 0.45",
                rationale: "Critically low trust. Session blocked. Security operations must be notified.".to_string(),
                requires_multi_sig: false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_engine::TrustScore;

    fn trust(score: f64) -> TrustScore {
        TrustScore { score, confidence: 0.9, reasons: vec![] }
    }

    #[test]
    fn test_high_trust_allows() {
        let result = PolicyEngine::enforce(&trust(0.92));
        assert_eq!(result.decision, PolicyDecision::Allow);
        assert!(!result.requires_multi_sig);
    }

    #[test]
    fn test_moderate_trust_requires_mfa() {
        let result = PolicyEngine::enforce(&trust(0.75));
        assert_eq!(result.decision, PolicyDecision::RequireMFA);
    }

    #[test]
    fn test_low_trust_requires_approval_with_multisig() {
        let result = PolicyEngine::enforce(&trust(0.55));
        assert_eq!(result.decision, PolicyDecision::RequireApproval);
        assert!(result.requires_multi_sig);
    }

    #[test]
    fn test_very_low_trust_blocks() {
        let result = PolicyEngine::enforce(&trust(0.30));
        assert_eq!(result.decision, PolicyDecision::Block);
        assert!(!result.requires_multi_sig);
    }

    #[test]
    fn test_boundary_0_85_is_mfa_not_allow() {
        let result = PolicyEngine::enforce(&trust(0.85));
        assert_eq!(result.decision, PolicyDecision::RequireMFA);
    }
}
