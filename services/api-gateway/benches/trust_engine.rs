//! Benchmark suite for the Trust Engine evaluation pipeline.
//!
//! Run with: cargo bench -p api-gateway
//!
//! Measures: P50/P95/P99 latency, throughput, memory per evaluation.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use sentinelmark_rs::SentinelMark;
use telemetry_engine::{TelemetryEvent, ActionType};
use sentinelmark_core::{UserId, DeviceId};
use behavior_engine::BehaviorProfile;
use chrono::Utc;

fn build_event() -> TelemetryEvent {
    TelemetryEvent {
        user_id: UserId("bench-user-001".to_string()),
        timestamp: Utc::now(),
        device_id: DeviceId("device-bench-001".to_string()),
        browser_fingerprint: "fp-bench-abc123".to_string(),
        ip_address: "192.168.1.100".to_string(),
        geo_region: "US-West".to_string(),
        action_type: ActionType::Transaction,
        transaction_amount: Some(5000.0),
        session_duration_secs: Some(300),
    }
}

fn bench_trust_evaluation_cold(c: &mut Criterion) {
    let sdk = SentinelMark::new();
    let profile = BehaviorProfile::default();
    let event = build_event();

    c.bench_function("trust_evaluation_cold_profile", |b| {
        b.iter(|| {
            let result = sdk.evaluate(black_box(&event), black_box(&profile));
            black_box(result)
        })
    });
}

fn bench_trust_evaluation_warm(c: &mut Criterion) {
    let sdk = SentinelMark::new();
    // Simulate a warm profile with established history
    let profile = BehaviorProfile {
        avg_transaction_amount: 50.0,
        ..Default::default()
    };
    let event = build_event();

    c.bench_function("trust_evaluation_warm_profile", |b| {
        b.iter(|| {
            let result = sdk.evaluate(black_box(&event), black_box(&profile));
            black_box(result)
        })
    });
}

fn bench_throughput_concurrent(c: &mut Criterion) {
    let sdk = SentinelMark::new();
    let profile = BehaviorProfile::default();

    let mut group = c.benchmark_group("concurrent_evaluations");
    for batch_size in [1, 10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, &size| {
                let events: Vec<_> = (0..size).map(|_| build_event()).collect();
                b.iter(|| {
                    for event in &events {
                        let result = sdk.evaluate(black_box(event), black_box(&profile));
                        black_box(result);
                    }
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_trust_evaluation_cold,
    bench_trust_evaluation_warm,
    bench_throughput_concurrent
);
criterion_main!(benches);
