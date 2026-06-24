//! SentinelMark v2 — Attack Scenario Demonstrations
//!
//! Scenarios:
//!   1. Normal Login                → Allow
//!   2. New Device Login            → RequireMFA
//!   3. Impossible Travel           → RequireApproval
//!   4. Large Treasury Transfer     → Block
//!   5. Credential Theft            → Block
//!   6. Session Hijack              → RequireApproval

use sentinelmark_rs::SentinelMark;
use sentinelmark_core::{UserId, DeviceId};
use telemetry_engine::{TelemetryEvent, ActionType};
use behavior_engine::BehaviorProfile;
use policy_engine::PolicyDecision;
use chrono::Utc;
use std::collections::HashSet;

fn print_result(label: &str, event: &TelemetryEvent, profile: &BehaviorProfile, engine: &SentinelMark) {
    let r = engine.evaluate(event, profile);
    let decision_emoji = match r.decision {
        PolicyDecision::Allow          => "✅ ALLOW",
        PolicyDecision::RequireMFA     => "🔐 REQUIRE MFA",
        PolicyDecision::RequireApproval=> "⚠️  REQUIRE APPROVAL",
        PolicyDecision::Block          => "🚫 BLOCK",
    };
    println!("\n┌─────────────────────────────────────────");
    println!("│ Scenario: {}", label);
    println!("├─────────────────────────────────────────");
    println!("│ Risk Score  : {:.2}", r.risk_score);
    println!("│ Trust Score : {:.2}", r.trust_score);
    println!("│ Decision    : {}", decision_emoji);
    if r.requires_multi_sig { println!("│ Multi-Sig   : Required"); }
    if !r.reasons.is_empty() { println!("│ Reasons     : {:?}", r.reasons); }
    println!("│ Note        : {}", r.explanation);
    println!("└─────────────────────────────────────────");
}

fn established_profile() -> BehaviorProfile {
    let mut known_devices = HashSet::new();
    known_devices.insert("dev-macbook-pro".to_string());
    let mut known_regions = HashSet::new();
    known_regions.insert("US-East".to_string());
    BehaviorProfile {
        known_devices,
        known_regions,
        avg_transaction_amount: 500.0,
    }
}

fn base_event() -> TelemetryEvent {
    TelemetryEvent {
        user_id: UserId("alice123".to_string()),
        timestamp: Utc::now(),
        device_id: DeviceId("dev-macbook-pro".to_string()),
        browser_fingerprint: "fp-abc123".to_string(),
        ip_address: "192.168.1.10".to_string(),
        geo_region: "US-East".to_string(),
        action_type: ActionType::Login,
        transaction_amount: None,
        session_duration_secs: Some(300),
    }
}

fn main() {
    println!("╔════════════════════════════════════════════╗");
    println!("║  SentinelMark v2 — Attack Scenario Suite  ║");
    println!("╚════════════════════════════════════════════╝");

    let engine = SentinelMark::new();
    let profile = established_profile();

    // ── 1. Normal Login ─────────────────────────────────────────────────────────
    let mut event = base_event();
    print_result("1. Normal Login", &event, &profile, &engine);

    // ── 2. New Device Login ─────────────────────────────────────────────────────
    event.device_id = DeviceId("dev-unknown-android".to_string());
    print_result("2. New Device Login", &event, &profile, &engine);

    // ── 3. Impossible Travel ────────────────────────────────────────────────────
    event.device_id = DeviceId("dev-macbook-pro".to_string());
    event.geo_region = "CN-Shanghai".to_string();
    event.ip_address = "60.191.45.82".to_string();
    print_result("3. Impossible Travel (geo changed within minutes)", &event, &profile, &engine);

    // ── 4. Large Treasury Transfer ──────────────────────────────────────────────
    event.geo_region = "US-East".to_string();
    event.ip_address = "192.168.1.10".to_string();
    event.action_type = ActionType::Transaction;
    event.transaction_amount = Some(250_000.0); // 500x normal avg
    print_result("4. Large Treasury Transfer (250,000 XLM)", &event, &profile, &engine);

    // ── 5. Credential Theft (known IP, unknown device, large transfer) ───────────
    event.transaction_amount = Some(75_000.0);
    event.device_id = DeviceId("dev-attacker".to_string()); // Unknown device
    print_result("5. Credential Theft (known IP, stolen session, large transfer)", &event, &profile, &engine);

    // ── 6. Session Hijack (new device + unusual region) ─────────────────────────
    event.transaction_amount = None;
    event.action_type = ActionType::SessionPing;
    event.geo_region = "RU-Moscow".to_string();
    event.device_id = DeviceId("dev-hijacker".to_string());
    print_result("6. Session Hijack (unknown device + unusual region)", &event, &profile, &engine);
}
