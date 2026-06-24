//! Workflow Engine
//!
//! Tracks session action sequences and detects anomalous workflow patterns.
//! All computation is pure and deterministic.
//!
//! Normal workflow example:
//!   Login → Dashboard → Reports → Logout
//!
//! Anomalous workflow example:
//!   Login → BulkExport → LargeTransfer → Logout
//!   (skips approval gates, abnormal sequencing)

use serde::{Deserialize, Serialize};
use telemetry_engine::ActionType;

/// A named, ordered workflow that the system considers "normal" for a role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub name: String,
    /// Ordered list of expected action types as string labels.
    pub expected_sequence: Vec<String>,
}

/// Records the actions a user performed in the current session.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionWorkflow {
    pub actions: Vec<String>,
}

impl SessionWorkflow {
    pub fn push(&mut self, action: &ActionType) {
        self.actions.push(format!("{:?}", action));
    }
}

/// Result of comparing an observed session against the expected workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDeviationReport {
    pub is_deviated: bool,
    pub skipped_steps: Vec<String>,
    pub unexpected_steps: Vec<String>,
    pub deviation_ratio: f64,
    pub explanation: String,
}

pub struct WorkflowEngine;

impl WorkflowEngine {
    /// Compare observed session actions against a defined baseline workflow.
    pub fn analyze(session: &SessionWorkflow, definition: &WorkflowDefinition) -> WorkflowDeviationReport {
        let expected: std::collections::HashSet<&String> =
            definition.expected_sequence.iter().collect();
        let observed: std::collections::HashSet<&String> =
            session.actions.iter().collect();

        let skipped_steps: Vec<String> = expected
            .difference(&observed)
            .map(|s| s.to_string())
            .collect();

        let unexpected_steps: Vec<String> = observed
            .difference(&expected)
            .map(|s| s.to_string())
            .collect();

        let total = expected.len().max(1) as f64;
        let deviation_ratio = skipped_steps.len() as f64 / total;
        let is_deviated = deviation_ratio > 0.25 || !unexpected_steps.is_empty();

        let explanation = if is_deviated {
            format!(
                "Workflow deviated by {:.0}%. Unexpected: {:?}. Skipped: {:?}.",
                deviation_ratio * 100.0,
                unexpected_steps,
                skipped_steps
            )
        } else {
            "Workflow matches expected sequence.".to_string()
        };

        WorkflowDeviationReport {
            is_deviated,
            skipped_steps,
            unexpected_steps,
            deviation_ratio,
            explanation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn standard_definition() -> WorkflowDefinition {
        WorkflowDefinition {
            name: "Standard Session".to_string(),
            expected_sequence: vec![
                "Login".to_string(),
                "Dashboard".to_string(),
                "Reports".to_string(),
                "Logout".to_string(),
            ],
        }
    }

    #[test]
    fn test_normal_workflow_no_deviation() {
        let def = standard_definition();
        let session = SessionWorkflow {
            actions: vec![
                "Login".to_string(),
                "Dashboard".to_string(),
                "Reports".to_string(),
                "Logout".to_string(),
            ],
        };
        let report = WorkflowEngine::analyze(&session, &def);
        assert!(!report.is_deviated);
        assert_eq!(report.deviation_ratio, 0.0);
    }

    #[test]
    fn test_bulk_export_triggers_deviation() {
        let def = standard_definition();
        let session = SessionWorkflow {
            actions: vec![
                "Login".to_string(),
                "BulkExport".to_string(),
                "Transaction".to_string(),
            ],
        };
        let report = WorkflowEngine::analyze(&session, &def);
        assert!(report.is_deviated);
        assert!(report.unexpected_steps.contains(&"BulkExport".to_string()));
    }
}
