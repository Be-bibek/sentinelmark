//! # Integration Test: BEW End-to-End Protocol
//!
//! Tests the full Phase 1 protocol:
//!   1. Capture behavioral fingerprint
//!   2. Construct telemetry event with nonce
//!   3. Derive BEW watermark
//!   4. Finalize event (compute current_hash)
//!   5. Append to chain
//!   6. Verify watermark (constant-time)
//!   7. Verify full chain integrity

use sentinelmark_core::{
    behavior::BehaviorSnapshot,
    chain::{ChainManager, GENESIS_HASH},
    telemetry::TelemetryEvent,
    verifier::Verifier,
    watermark::{StaticKey, WatermarkEngine},
};

/// A hex-encoded 256-bit static key for tests.
/// In production, this comes from a HSM or TPM.
const TEST_KEY_HEX: &str =
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

fn make_engine() -> WatermarkEngine {
    WatermarkEngine::new(StaticKey::from_hex(TEST_KEY_HEX).unwrap())
}

fn make_verifier() -> Verifier {
    Verifier::new(make_engine())
}

/// Full protocol: single event, end-to-end.
#[test]
fn test_single_event_bew_protocol() {
    let engine = make_engine();
    let verifier = make_verifier();

    // Step 1: Behavioral fingerprint
    let snap = BehaviorSnapshot {
        cpu_usage_pct_x100:    5000,
        virtual_memory_bytes:  1_073_741_824,
        physical_memory_bytes: 512_000_000,
        thread_count:          8,
        jitter_ns:             25_000,
        captured_at_unix_secs: 1_700_000_000,
    };
    let behavior = snap.to_digest();

    // Step 2: Construct telemetry event
    let mut event = TelemetryEvent::new(
        "device-001",
        GENESIS_HASH,
        serde_json::json!({"sensor": "cpu_temp", "value": 72.3}),
    )
    .expect("event construction must succeed");

    // Step 3: Derive BEW watermark
    let watermark = engine
        .derive(&behavior, &event.prev_hash, &event.nonce)
        .expect("derivation must succeed");

    // Step 4: Set watermark and finalize (compute current_hash)
    event.set_watermark(watermark.into_bytes());
    event.finalize().expect("finalize must succeed");

    // Step 5: Append to chain
    let mut chain = ChainManager::new();
    chain.append(&event).expect("chain append must succeed");
    assert_eq!(chain.event_count(), 1);

    // Step 6: Verify watermark (constant-time comparison)
    let is_valid = verifier
        .verify_watermark(&event, &behavior)
        .expect("verification must not error");
    assert!(is_valid, "BEW watermark must verify against the same inputs");
}

/// Chain of 3 events must verify completely.
#[test]
fn test_three_event_chain_end_to_end() {
    let engine = make_engine();
    let verifier = make_verifier();
    let mut chain_mgr = ChainManager::new();
    let mut events = Vec::new();
    let mut prev_hash = GENESIS_HASH;

    for i in 0..3 {
        let snap = BehaviorSnapshot {
            cpu_usage_pct_x100:    (i * 1000) as u32,
            virtual_memory_bytes:  512_000_000 + i as u64 * 1024,
            physical_memory_bytes: 256_000_000,
            thread_count:          4 + i as u32,
            jitter_ns:             10_000 + i as u64 * 500,
            captured_at_unix_secs: 1_700_000_000 + i as u64,
        };
        let behavior = snap.to_digest();

        let mut event = TelemetryEvent::new(
            "device-chain-test",
            prev_hash,
            serde_json::json!({"seq": i}),
        )
        .unwrap();

        let wm = engine
            .derive(&behavior, &event.prev_hash, &event.nonce)
            .unwrap();
        event.set_watermark(wm.into_bytes());
        event.finalize().unwrap();

        chain_mgr.append(&event).expect("chain append must succeed");

        // Verify each event's watermark as it's appended
        let valid = verifier.verify_watermark(&event, &behavior).unwrap();
        assert!(valid, "event {} watermark must be valid", i);

        prev_hash = event.current_hash;
        events.push(event);
    }

    // Full chain verification
    ChainManager::verify_chain(&events).expect("full chain must verify");
    assert_eq!(chain_mgr.event_count(), 3);
}

/// A forged event (wrong watermark) must not verify.
#[test]
fn test_forged_watermark_rejected() {
    let verifier = make_verifier();

    let snap = BehaviorSnapshot {
        cpu_usage_pct_x100: 5000, virtual_memory_bytes: 1_000_000,
        physical_memory_bytes: 500_000, thread_count: 4,
        jitter_ns: 1_000, captured_at_unix_secs: 1_700_000_000,
    };
    let behavior = snap.to_digest();

    let mut event = TelemetryEvent::new(
        "device-forge-test",
        GENESIS_HASH,
        serde_json::json!({}),
    ).unwrap();

    // Set a FORGED watermark (all 0xFF, not derived from K_static)
    event.set_watermark([0xFF_u8; 32]);
    event.finalize().unwrap();

    let is_valid = verifier.verify_watermark(&event, &behavior).unwrap();
    assert!(
        !is_valid,
        "A forged watermark must NOT verify — BEW reject must hold"
    );
}

/// Replaying the same event must be detectable by chain (prev_hash violation).
#[test]
fn test_replay_breaks_chain() {
    let engine = make_engine();
    let snap = BehaviorSnapshot {
        cpu_usage_pct_x100: 0, virtual_memory_bytes: 0,
        physical_memory_bytes: 0, thread_count: 1,
        jitter_ns: 0, captured_at_unix_secs: 1_700_000_000,
    };
    let behavior = snap.to_digest();
    let mut chain = ChainManager::new();

    let mut event = TelemetryEvent::new("device", GENESIS_HASH, serde_json::json!({})).unwrap();
    let wm = engine.derive(&behavior, &event.prev_hash, &event.nonce).unwrap();
    event.set_watermark(wm.into_bytes());
    event.finalize().unwrap();
    chain.append(&event).unwrap();

    // Replay the same event — chain should reject it (prev_hash already advanced)
    let result = chain.append(&event);
    assert!(
        result.is_err(),
        "Replaying an event must break chain integrity"
    );
}
