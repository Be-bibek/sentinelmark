//! # Benchmark: Verification Throughput
//!
//! Measures watermark verification rate (events/second).
//! Phase 1 stub — grows with full verifier in Phase 2.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use sentinelmark_core::{
    behavior::BehaviorSnapshot,
    watermark::{WatermarkEngine, StaticKey},
    verifier::Verifier,
    telemetry::{TelemetryEvent, HASH_LEN},
};

fn bench_verify_single(c: &mut Criterion) {
    let key_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let engine = WatermarkEngine::new(StaticKey::from_hex(key_hex).unwrap());
    let verifier = Verifier::new(
        WatermarkEngine::new(StaticKey::from_hex(key_hex).unwrap())
    );

    let snap = BehaviorSnapshot {
        cpu_usage_pct_x100: 5000,
        virtual_memory_bytes: 1_073_741_824,
        physical_memory_bytes: 512_000_000,
        thread_count: 8, jitter_ns: 25_000,
        captured_at_unix_secs: 1_700_000_000,
    };
    let behavior = snap.to_digest();

    let mut event = TelemetryEvent::new(
        "bench-device", 1, [0u8; HASH_LEN], serde_json::json!({}),
    ).unwrap();

    let wm = engine.derive(&behavior, &event.prev_hash, &event.nonce).unwrap();
    event.set_watermark(wm.into_bytes());
    event.finalize().unwrap();

    c.benchmark_group("verification_throughput")
        .throughput(Throughput::Elements(1))
        .bench_function("verify_single_event", |b| {
            b.iter(|| {
                verifier.verify_watermark(black_box(&event), black_box(&behavior)).unwrap()
            })
        });
}

criterion_group!(benches, bench_verify_single);
criterion_main!(benches);
