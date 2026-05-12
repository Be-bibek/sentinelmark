//! # Benchmark: Chain Integrity Verification Throughput
//!
//! Measures the cost of verifying an N-event chain.
//! Phase 1 stub — content grows with Phase 2 chain verifier.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sentinelmark_core::{
    chain::{ChainManager, GENESIS_HASH},
    telemetry::{TelemetryEvent, WATERMARK_LEN, HASH_LEN},
};

fn make_chain(n: usize) -> Vec<TelemetryEvent> {
    let mut events = Vec::with_capacity(n);
    let mut prev = GENESIS_HASH;

    for i in 0..n {
        let mut e = TelemetryEvent::new(
            "bench-device",
            prev,
            serde_json::json!({"seq": i}),
        )
        .unwrap();
        e.set_watermark([0xaa_u8; WATERMARK_LEN]);
        e.finalize().unwrap();
        prev = e.current_hash;
        events.push(e);
    }

    events
}

fn bench_chain_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_verify");

    for n in [10usize, 100, 1_000].iter() {
        let chain = make_chain(*n);
        group.throughput(Throughput::Elements(*n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, _| {
            b.iter(|| {
                ChainManager::verify_chain(black_box(&chain))
                    .expect("bench chain must be valid")
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_chain_verify);
criterion_main!(benches);
