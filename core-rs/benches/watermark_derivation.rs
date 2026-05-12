//! # Benchmark: Watermark Derivation Latency
//!
//! Measures the end-to-end BEW derivation cost:
//! `HKDF-SHA256(K_static || BehaviorFingerprint_i || H_prev, nonce)`
//!
//! ## Benchmark Groups
//!
//! | Group | What it isolates |
//! |---|---|
//! | `watermark_derive_cold` | Single derivation, no caching |
//! | `watermark_derive_batch_100` | 100 sequential derivations |
//! | `behavior_snapshot_to_digest` | Cost of behavioral fingerprinting only |
//! | `hkdf_only_32b` | Raw HKDF cost (lower bound) |
//!
//! ## How to run
//! ```bash
//! cargo bench --bench watermark_derivation
//! ```
//!
//! ## IEEE Reporting
//! Results are saved to `target/criterion/watermark_derivation/`.
//! Use `cargo criterion` (install: `cargo install cargo-criterion`) for
//! machine-readable JSON output suitable for table generation.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sentinelmark_core::{
    behavior::{BehaviorSnapshot, BehaviorSampler},
    watermark::{WatermarkEngine, StaticKey},
    crypto::{hkdf_derive, HKDF_INFO},
};

// ─── Test fixtures ───────────────────────────────────────────────────────────

fn bench_engine() -> WatermarkEngine {
    let key = StaticKey::from_hex(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    )
    .unwrap();
    WatermarkEngine::new(key)
}

fn bench_behavior() -> sentinelmark_core::behavior::BehaviorDigest {
    BehaviorSnapshot {
        cpu_usage_pct_x100:    5000,
        virtual_memory_bytes:  1_073_741_824,
        physical_memory_bytes: 512_000_000,
        thread_count:          8,
        jitter_ns:             25_000,
        captured_at_unix_secs: 1_700_000_000,
    }
    .to_digest()
}

// ─── Benchmark: single derivation ───────────────────────────────────────────

fn bench_watermark_derive_single(c: &mut Criterion) {
    let engine = bench_engine();
    let behavior = bench_behavior();
    let prev_hash = [0u8; 32];
    let nonce = [0xab_u8; 32];

    c.bench_function("watermark_derive_single", |b| {
        b.iter(|| {
            engine
                .derive(
                    black_box(&behavior),
                    black_box(&prev_hash),
                    black_box(&nonce),
                )
                .expect("bench derivation must not fail")
        })
    });
}

// ─── Benchmark: batch derivation throughput ──────────────────────────────────

fn bench_watermark_derive_batch(c: &mut Criterion) {
    let engine = bench_engine();
    let behavior = bench_behavior();
    let prev_hash = [0u8; 32];
    let nonce = [0xcd_u8; 32];

    let mut group = c.benchmark_group("watermark_derive_batch");

    for batch_size in [1u64, 10, 100, 1_000].iter() {
        group.throughput(Throughput::Elements(*batch_size));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            batch_size,
            |b, &n| {
                b.iter(|| {
                    for _ in 0..n {
                        let _ = engine
                            .derive(
                                black_box(&behavior),
                                black_box(&prev_hash),
                                black_box(&nonce),
                            )
                            .expect("bench derivation must not fail");
                    }
                })
            },
        );
    }

    group.finish();
}

// ─── Benchmark: behavior snapshot digest only ───────────────────────────────

fn bench_behavior_digest(c: &mut Criterion) {
    let snap = BehaviorSnapshot {
        cpu_usage_pct_x100:    5000,
        virtual_memory_bytes:  1_073_741_824,
        physical_memory_bytes: 512_000_000,
        thread_count:          8,
        jitter_ns:             25_000,
        captured_at_unix_secs: 1_700_000_000,
    };

    c.bench_function("behavior_snapshot_to_digest", |b| {
        b.iter(|| black_box(&snap).to_digest())
    });
}

// ─── Benchmark: raw HKDF lower bound ────────────────────────────────────────

fn bench_hkdf_raw(c: &mut Criterion) {
    let ikm = [0x42u8; 96];  // simulates K_static || BehFP || H_prev
    let salt = [0xab_u8; 32];

    c.bench_function("hkdf_sha256_96b_ikm", |b| {
        b.iter(|| {
            hkdf_derive(black_box(&ikm), black_box(&salt), HKDF_INFO)
                .expect("bench hkdf must not fail")
        })
    });
}

// ─── Criterion entrypoint ────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_watermark_derive_single,
    bench_watermark_derive_batch,
    bench_behavior_digest,
    bench_hkdf_raw,
);
criterion_main!(benches);
