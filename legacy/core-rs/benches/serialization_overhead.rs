//! # Benchmark: Serialization Overhead
//!
//! Compares `serde_json` vs `rkyv` for telemetry event encoding.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinelmark_core::telemetry::{TelemetryEvent, WATERMARK_LEN, HASH_LEN};

fn make_event() -> TelemetryEvent {
    let mut e = TelemetryEvent::new(
        "bench-device",
        1,
        [0u8; HASH_LEN],
        serde_json::json!({"metric": "cpu", "value": 42}),
    )
    .unwrap();
    e.set_watermark([0xde_u8; WATERMARK_LEN]);
    e.finalize().unwrap();
    e
}

fn bench_serde_json_serialize(c: &mut Criterion) {
    let event = make_event();
    c.bench_function("serde_json_serialize", |b| {
        b.iter(|| serde_json::to_vec(black_box(&event)).unwrap())
    });
}

fn bench_serde_json_deserialize(c: &mut Criterion) {
    let event = make_event();
    let json = serde_json::to_vec(&event).unwrap();
    c.bench_function("serde_json_deserialize", |b| {
        b.iter(|| {
            let _: TelemetryEvent = serde_json::from_slice(black_box(&json)).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_serde_json_serialize,
    bench_serde_json_deserialize,
);
criterion_main!(benches);
