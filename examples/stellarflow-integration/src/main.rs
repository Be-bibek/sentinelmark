//! StellarFlow Treasury Integration Demo
//!
//! Demonstrates SentinelMark v2 as a blockchain-agnostic trust gating layer.
//!
//! StellarFlow consumes the SentinelMark SDK to authorize treasury operations.
//! SentinelMark does NOT know about Stellar. Trust infrastructure is the product.
//! Blockchain integration is only an example consumer.

use sentinelmark_rs::SentinelMark;
use sentinelmark_core::{UserId, DeviceId};
use telemetry_engine::{TelemetryEvent, ActionType};
use behavior_engine::BehaviorProfile;
use policy_engine::PolicyDecision;
use chrono::Utc;
use std::collections::HashSet;

fn authorize_transfer(engine: &SentinelMark, profile: &BehaviorProfile, event: &TelemetryEvent, amount: f64) {
    let result = engine.evaluate(event, profile);
    println!("  Trust Score    : {:.2}", result.trust_score);
    println!("  Risk Score     : {:.2}", result.risk_score);
    println!("  Decision       : {:?}", result.decision);
    if result.requires_multi_sig { println!("  Multi-Sig      : Required — escalating to approval queue"); }
    if !result.reasons.is_empty() { println!("  Risk Factors   : {:?}", result.reasons); }
    println!("  Explanation    : {}", result.explanation);

    match result.decision {
        PolicyDecision::Allow => {
            println!("  Action         : ✅ Executing transfer of {:.0} XLM immediately.", amount);
        }
        PolicyDecision::RequireMFA => {
            println!("  Action         : 🔐 MFA challenge sent. Transfer pending confirmation.");
        }
        PolicyDecision::RequireApproval => {
            println!("  Action         : ⚠️  Transfer of {:.0} XLM escalated to Multi-Sig approval.", amount);
        }
        PolicyDecision::Block => {
            println!("  Action         : 🚫 Transfer BLOCKED. Session terminated.");
        }
    }
}

fn main() {
    println!("╔═════════════════════════════════════════════╗");
    println!("║  StellarFlow × SentinelMark v2 Demo         ║");
    println!("╚═════════════════════════════════════════════╝");

    let engine = SentinelMark::new();

    let mut known_devices = HashSet::new();
    known_devices.insert("dev-macbook-pro".to_string());
    let mut known_regions = HashSet::new();
    known_regions.insert("US-East".to_string());

    let profile = BehaviorProfile {
        known_devices,
        known_regions,
        avg_transaction_amount: 250.0,
    };

    println!("\n[Scenario 1] Normal treasury transfer — 500 XLM");
    let event1 = TelemetryEvent {
        user_id: UserId("alice123".to_string()),
        timestamp: Utc::now(),
        device_id: DeviceId("dev-macbook-pro".to_string()),
        browser_fingerprint: "fp-abc123".to_string(),
        ip_address: "192.168.1.10".to_string(),
        geo_region: "US-East".to_string(),
        action_type: ActionType::Transaction,
        transaction_amount: Some(500.0),
        session_duration_secs: Some(300),
    };
    authorize_transfer(&engine, &profile, &event1, 500.0);

    println!("\n[Scenario 2] Anomalous treasury transfer — 50,000 XLM from unknown region");
    let event2 = TelemetryEvent {
        user_id: UserId("alice123".to_string()),
        timestamp: Utc::now(),
        device_id: DeviceId("dev-macbook-pro".to_string()),
        browser_fingerprint: "fp-abc123".to_string(),
        ip_address: "45.22.11.9".to_string(),
        geo_region: "RU-Moscow".to_string(), // Unknown region
        action_type: ActionType::Transaction,
        transaction_amount: Some(50_000.0),  // 200x normal avg
        session_duration_secs: Some(30),
    };
    authorize_transfer(&engine, &profile, &event2, 50_000.0);
}
