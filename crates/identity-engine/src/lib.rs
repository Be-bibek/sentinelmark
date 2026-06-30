//! Identity Engine
//!
//! Manages identity claims, device trust levels, and session binding.
//! Detects impossible-travel scenarios and credential anomalies.
//! Pure, deterministic — no network I/O.

use chrono::{DateTime, Utc};
use sentinelmark_core::{DeviceId, UserId};
use serde::{Deserialize, Serialize};

/// Trust classification for a specific device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceTrustLevel {
    Trusted,    // Previously seen, no anomalies
    Unknown,    // First time seen
    Suspicious, // Previously flagged or showing anomalous signals
}

/// A snapshot of an authenticated identity's context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityClaim {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub ip_address: String,
    pub geo_region: String,
    pub asserted_at: DateTime<Utc>,
    pub device_trust: DeviceTrustLevel,
}

/// Result of evaluating a new claim against the last-known identity state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAssessment {
    pub is_impossible_travel: bool,
    pub is_new_device: bool,
    pub is_credential_reuse_risk: bool,
    pub explanation: String,
}

/// The last-known state of a user's identity context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityState {
    pub last_ip: String,
    pub last_geo_region: String,
    pub last_seen_at: DateTime<Utc>,
    pub known_device_ids: Vec<String>,
}

pub struct IdentityEngine;

impl IdentityEngine {
    /// Evaluate a new identity claim against the user's known state.
    pub fn assess(claim: &IdentityClaim, state: &IdentityState) -> IdentityAssessment {
        // Impossible travel: different region in a very short time window
        let elapsed_minutes = (claim.asserted_at - state.last_seen_at).num_minutes();
        let is_impossible_travel =
            claim.geo_region != state.last_geo_region && elapsed_minutes < 120;

        let is_new_device = !state.known_device_ids.contains(&claim.device_id.0);

        // Credential reuse risk: same IP but different device fingerprint
        let is_credential_reuse_risk = claim.ip_address == state.last_ip && is_new_device;

        let mut parts = vec![];
        if is_impossible_travel {
            parts.push(format!(
                "Impossible travel detected: region changed from {} to {} within {} minutes.",
                state.last_geo_region, claim.geo_region, elapsed_minutes
            ));
        }
        if is_new_device {
            parts.push("Unrecognized device fingerprint.".to_string());
        }
        if is_credential_reuse_risk {
            parts.push(
                "Same IP with an unrecognized device may indicate credential reuse.".to_string(),
            );
        }
        if parts.is_empty() {
            parts.push("Identity context matches known state.".to_string());
        }

        IdentityAssessment {
            is_impossible_travel,
            is_new_device,
            is_credential_reuse_risk,
            explanation: parts.join(" "),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_state() -> IdentityState {
        IdentityState {
            last_ip: "192.168.1.10".to_string(),
            last_geo_region: "US-East".to_string(),
            last_seen_at: Utc::now() - chrono::Duration::minutes(10),
            known_device_ids: vec!["dev-macbook".to_string()],
        }
    }

    #[test]
    fn test_normal_login_no_anomaly() {
        let state = base_state();
        let claim = IdentityClaim {
            user_id: UserId("alice".to_string()),
            device_id: DeviceId("dev-macbook".to_string()),
            ip_address: "192.168.1.10".to_string(),
            geo_region: "US-East".to_string(),
            asserted_at: Utc::now(),
            device_trust: DeviceTrustLevel::Trusted,
        };
        let assessment = IdentityEngine::assess(&claim, &state);
        assert!(!assessment.is_impossible_travel);
        assert!(!assessment.is_new_device);
        assert!(!assessment.is_credential_reuse_risk);
    }

    #[test]
    fn test_impossible_travel_detection() {
        let state = base_state();
        let claim = IdentityClaim {
            user_id: UserId("alice".to_string()),
            device_id: DeviceId("dev-macbook".to_string()),
            ip_address: "91.100.22.5".to_string(),
            geo_region: "RU-Moscow".to_string(), // Changed within 10 minutes
            asserted_at: Utc::now(),
            device_trust: DeviceTrustLevel::Unknown,
        };
        let assessment = IdentityEngine::assess(&claim, &state);
        assert!(assessment.is_impossible_travel);
    }
}
