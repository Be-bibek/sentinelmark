//! Explainability Engine
//!
//! Converts raw risk factors and trust scores into structured, human-readable
//! audit narratives suitable for enterprise security review, compliance reporting,
//! and operator dashboards.
//!
//! Trust decisions must never be opaque. Every decision must be explainable.

use policy_engine::PolicyDecision;
use risk_engine::RiskAssessment;
use sentinelmark_core::FactorExplanation;
use serde::{Deserialize, Serialize};
use trust_engine::TrustScore;

/// A fully explained, human-readable trust evaluation narrative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustNarrative {
    pub summary: String,
    pub risk_score: f64,
    pub trust_score: f64,
    pub decision: PolicyDecision,
    pub factors: Vec<FactorExplanation>,
    pub recommendation: String,
    pub compliance_note: String,
}

pub struct ExplainabilityEngine;

impl ExplainabilityEngine {
    /// Generate a structured narrative from raw engine outputs.
    pub fn explain(
        risk: &RiskAssessment,
        trust: &TrustScore,
        decision: &PolicyDecision,
    ) -> TrustNarrative {
        let factors = Self::build_factor_explanations(risk);

        let summary = format!(
            "Trust score of {:.2} (confidence: {:.0}%) derived from {} active risk factor(s).",
            trust.score,
            trust.confidence * 100.0,
            risk.factors.len()
        );

        let recommendation = match decision {
            PolicyDecision::Allow => {
                "No additional authentication required. Proceed normally.".to_string()
            }
            PolicyDecision::RequireMFA => {
                "Step-up authentication required before sensitive operations are permitted."
                    .to_string()
            }
            PolicyDecision::RequireApproval => {
                "Manual supervisor approval required. Escalate to multi-sig authorization flow."
                    .to_string()
            }
            PolicyDecision::Block => {
                "Session must be terminated immediately. Notify security operations.".to_string()
            }
        };

        let compliance_note = match decision {
            PolicyDecision::Allow | PolicyDecision::RequireMFA => {
                "Decision compliant with HIPAA §164.312(b) access controls.".to_string()
            }
            PolicyDecision::RequireApproval | PolicyDecision::Block => {
                "Incident requires audit log retention per FDA 21 CFR Part 11 and IHE ATNA §3.20."
                    .to_string()
            }
        };

        TrustNarrative {
            summary,
            risk_score: risk.score,
            trust_score: trust.score,
            decision: decision.clone(),
            factors,
            recommendation,
            compliance_note,
        }
    }

    fn build_factor_explanations(risk: &RiskAssessment) -> Vec<FactorExplanation> {
        risk.explained_factors
            .iter()
            .map(|(factor, detail, weight)| FactorExplanation {
                factor: factor.clone(),
                detail: detail.clone(),
                weight: *weight,
            })
            .collect()
    }
}
