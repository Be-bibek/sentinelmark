use risk_engine::RiskAssessment;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub score: f64, // 0.0 to 1.0
    pub confidence: f64,
    pub reasons: Vec<String>,
}

pub struct TrustEngine;

impl TrustEngine {
    pub fn evaluate(risk: &RiskAssessment) -> TrustScore {
        // Trust is inversely proportional to Risk
        let score = 1.0 - risk.score;
        let confidence = 0.9; // Deterministic constant for this implementation

        TrustScore {
            score,
            confidence,
            reasons: risk.factors.clone(),
        }
    }
}
