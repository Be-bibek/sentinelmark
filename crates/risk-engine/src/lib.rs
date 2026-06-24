//! Risk Engine
//!
//! Pure, deterministic, weighted scoring engine.
//! Converts behavioral deviation reports into structured risk assessments.
//! No network I/O, no randomness, no ML.

use serde::{Deserialize, Serialize};
use behavior_engine::BehaviorDeviationReport;

/// A fully structured risk assessment with per-factor human-readable explanations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Composite risk score in [0.0, 1.0]. Higher = riskier.
    pub score: f64,
    /// High-level factor labels (for backward compatibility).
    pub factors: Vec<String>,
    /// Per-factor explanation tuples: (factor label, detail, weight applied).
    pub explained_factors: Vec<(String, String, f64)>,
    /// Human-readable narrative of the overall assessment.
    pub explanation: String,
}

pub struct RiskEngine;

impl RiskEngine {
    /// Deterministic weighted risk scoring from a BehaviorDeviationReport.
    pub fn assess(report: &BehaviorDeviationReport) -> RiskAssessment {
        let mut score = 0.0f64;
        let mut factors = Vec::new();
        let mut explained_factors = Vec::new();

        if report.new_device {
            let w = 0.20;
            score += w;
            factors.push("New device detected".to_string());
            explained_factors.push((
                "New Device".to_string(),
                "Authentication from an unrecognized device fingerprint.".to_string(),
                w,
            ));
        }
        if report.unusual_location {
            let w = 0.25;
            score += w;
            factors.push("Unusual geographic region".to_string());
            explained_factors.push((
                "Unusual Location".to_string(),
                "Login originated from a region not in the user's historical profile.".to_string(),
                w,
            ));
        }
        if report.unusual_login_time {
            let w = 0.15;
            score += w;
            factors.push("Login outside historical window".to_string());
            explained_factors.push((
                "Unusual Login Time".to_string(),
                "Login occurred outside the user's normal working hours baseline.".to_string(),
                w,
            ));
        }
        if report.abnormal_session_duration {
            let w = 0.10;
            score += w;
            factors.push("Abnormal session duration".to_string());
            explained_factors.push((
                "Abnormal Session Duration".to_string(),
                "Session length deviates significantly from the user's baseline.".to_string(),
                w,
            ));
        }
        if report.abnormal_transaction_amount {
            let w = 0.40;
            score += w;
            factors.push("Abnormal transaction volume".to_string());
            explained_factors.push((
                "Abnormal Transaction Amount".to_string(),
                "Transaction amount is significantly outside the user's historical range.".to_string(),
                w,
            ));
        }
        if report.abnormal_workflow_sequence {
            let w = 0.20;
            score += w;
            factors.push("Abnormal workflow sequence".to_string());
            explained_factors.push((
                "Abnormal Workflow".to_string(),
                "Action sequence deviates from expected workflow pattern.".to_string(),
                w,
            ));
        }

        score = score.min(1.0);

        let explanation = if score == 0.0 {
            "No risk factors detected. Behavior matches established profile.".to_string()
        } else if score < 0.35 {
            format!("Low risk ({:.2}). Minor deviations detected but within acceptable thresholds.", score)
        } else if score < 0.65 {
            format!("Moderate risk ({:.2}). Multiple behavioral deviations require step-up authentication.", score)
        } else {
            format!("High risk ({:.2}). Significant behavioral anomalies detected. Approval or block recommended.", score)
        };

        RiskAssessment {
            score,
            factors,
            explained_factors,
            explanation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use behavior_engine::{BehaviorDeviationReport, Severity};

    fn clean_report() -> BehaviorDeviationReport {
        BehaviorDeviationReport {
            new_device: false,
            unusual_location: false,
            unusual_login_time: false,
            abnormal_session_duration: false,
            abnormal_transaction_amount: false,
            abnormal_workflow_sequence: false,
            overall_severity: Severity::Low,
        }
    }

    #[test]
    fn test_zero_risk_when_no_deviations() {
        let report = clean_report();
        let assessment = RiskEngine::assess(&report);
        assert_eq!(assessment.score, 0.0);
        assert!(assessment.factors.is_empty());
    }

    #[test]
    fn test_new_device_adds_0_20() {
        let mut report = clean_report();
        report.new_device = true;
        let assessment = RiskEngine::assess(&report);
        assert!((assessment.score - 0.20).abs() < 1e-9);
    }

    #[test]
    fn test_score_capped_at_1_0() {
        let report = BehaviorDeviationReport {
            new_device: true,
            unusual_location: true,
            unusual_login_time: true,
            abnormal_session_duration: true,
            abnormal_transaction_amount: true,
            abnormal_workflow_sequence: true,
            overall_severity: Severity::Critical,
        };
        let assessment = RiskEngine::assess(&report);
        assert!(assessment.score <= 1.0);
    }

    #[test]
    fn test_high_transaction_adds_0_40() {
        let mut report = clean_report();
        report.abnormal_transaction_amount = true;
        let assessment = RiskEngine::assess(&report);
        assert!((assessment.score - 0.40).abs() < 1e-9);
    }
}
