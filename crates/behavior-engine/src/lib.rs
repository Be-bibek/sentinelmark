use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use telemetry_engine::TelemetryEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorProfile {
    pub known_devices: HashSet<String>,
    pub known_regions: HashSet<String>,
    pub avg_transaction_amount: f64,
}

impl Default for BehaviorProfile {
    fn default() -> Self {
        Self {
            known_devices: HashSet::new(),
            known_regions: HashSet::new(),
            avg_transaction_amount: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorDeviationReport {
    pub new_device: bool,
    pub unusual_location: bool,
    pub unusual_login_time: bool,
    pub abnormal_session_duration: bool,
    pub abnormal_transaction_amount: bool,
    pub abnormal_workflow_sequence: bool,
    pub overall_severity: Severity,
}

pub struct BehaviorEngine;

impl BehaviorEngine {
    pub fn detect_deviations(
        profile: &BehaviorProfile,
        event: &TelemetryEvent,
    ) -> BehaviorDeviationReport {
        let new_device = !profile.known_devices.contains(&event.device_id.0);
        let unusual_location = !profile.known_regions.contains(&event.geo_region);

        let mut abnormal_transaction_amount = false;
        if let Some(amt) = event.transaction_amount {
            // Simplistic rule for deterministic behavior
            if profile.avg_transaction_amount > 0.0 && amt > profile.avg_transaction_amount * 5.0 {
                abnormal_transaction_amount = true;
            } else if profile.avg_transaction_amount == 0.0 && amt > 1000.0 {
                // If new profile and large amount
                abnormal_transaction_amount = true;
            }
        }

        let mut risk_factors = 0;
        if new_device {
            risk_factors += 1;
        }
        if unusual_location {
            risk_factors += 1;
        }
        if abnormal_transaction_amount {
            risk_factors += 2;
        }

        let overall_severity = match risk_factors {
            0 => Severity::Low,
            1 => Severity::Medium,
            2 => Severity::High,
            _ => Severity::Critical,
        };

        BehaviorDeviationReport {
            new_device,
            unusual_location,
            unusual_login_time: false,        // Stubbed for example
            abnormal_session_duration: false, // Stubbed for example
            abnormal_transaction_amount,
            abnormal_workflow_sequence: false, // Stubbed for example
            overall_severity,
        }
    }
}
