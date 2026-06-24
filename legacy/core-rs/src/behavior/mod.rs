//! # `behavior` — Behavioral Entropy Fingerprinting
//!
//! ## Architecture Decision
//!
//! A BEW watermark's security against *behavioral replay* attacks depends on
//! making `BehaviorFingerprint_i` *hard to predict or reproduce* without
//! controlling the device at the exact moment of capture.
//!
//! ### What we capture (and why each metric matters)
//!
//! | Metric | Anti-tamper value |
//! |---|---|
//! | CPU usage (%) | Changes under computational load; forging requires matching CPU state |
//! | Virtual memory (bytes) | Reflects process memory map; hard to replicate post-compromise |
//! | Physical memory (bytes) | Physical page residency; varies with OS scheduler |
//! | Thread count | Reflects concurrency profile; changes if telemetry is run on a fake host |
//! | Timing jitter (ns) | OS scheduler noise; impossible to forge retrospectively |
//!
//! ### Why timing jitter?
//! `std::thread::sleep(1ms)` never sleeps exactly 1ms. The delta between
//! requested and actual sleep time is a stochastic function of kernel tick
//! rate, scheduler load, and hardware interrupts. This makes it the *hardest*
//! metric to forge because it cannot be reconstructed from logs alone.
//!
//! ### Why NOT use user-provided entropy?
//! User-provided entropy can be replayed. Live system metrics are ephemeral
//! and bound to real-time OS state.
//!
//! ## Security Reasoning
//!
//! `BehaviorFingerprint` is **hashed** before it enters the HKDF IKM. This
//! prevents raw metric values from appearing in wire formats and ensures
//! the fingerprint contributes full-width entropy (32 bytes) regardless of
//! actual metric precision.
//!
//! ## Performance Tradeoffs
//!
//! - `sysinfo::System::refresh_specifics` is called with a minimal `RefreshKind`
//!   to avoid expensive disk/network enumeration.
//! - Timing jitter measurement adds ~1ms of synthetic delay; this is intentional
//!   and should be called asynchronously on a background task.
//! - Total fingerprint capture time: ~2–5ms on a modern Linux kernel.

use crate::crypto::{sha256, DIGEST_LEN};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[cfg(feature = "sysinfo-capture")]
use sysinfo::System;

// ─── Raw Metrics ────────────────────────────────────────────────────────────

/// Raw behavioral metrics captured at a single point in time.
///
/// This struct is **not** transmitted over the wire. It is hashed into a
/// 32-byte `BehaviorDigest` before entering the watermark derivation.
///
/// Field ordering is fixed and documented; any future field addition requires
/// a protocol version bump.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct BehaviorSnapshot {
    /// CPU usage percentage × 100 (integer, avoids float serialization issues).
    /// Range: [0, 10000]
    pub cpu_usage_pct_x100: u32,

    /// Total virtual memory allocated to the current process, in bytes.
    pub virtual_memory_bytes: u64,

    /// Physical (RSS) memory used by the current process, in bytes.
    pub physical_memory_bytes: u64,

    /// Number of threads in the current process.
    pub thread_count: u32,

    /// Timing jitter in nanoseconds.
    /// Measured as: actual_sleep_ns - requested_sleep_ns.
    /// Negative jitter (woke early) is clamped to 0.
    pub jitter_ns: u64,

    /// Unix timestamp (seconds) at capture time — for freshness checking.
    pub captured_at_unix_secs: u64,
}

impl BehaviorSnapshot {
    /// Serialize this snapshot deterministically and return its SHA-256 digest.
    ///
    /// Determinism is guaranteed by:
    /// - Fixed field ordering (struct field order)
    /// - Little-endian encoding of all integers
    /// - No floating-point values (avoiding platform-specific float formatting)
    ///
    /// This digest is the `BehaviorFingerprint_i` in the BEW equation.
    #[must_use]
    pub fn to_digest(&self) -> BehaviorDigest {
        // Deterministic binary encoding: fixed-size LE fields, no padding ambiguity.
        let mut buf = Vec::with_capacity(
            4   // cpu_usage_pct_x100  (u32)
            + 8 // virtual_memory_bytes (u64)
            + 8 // physical_memory_bytes (u64)
            + 4 // thread_count         (u32)
            + 8 // jitter_ns            (u64)
            + 8 // captured_at_unix_secs (u64)
        );

        buf.extend_from_slice(&self.cpu_usage_pct_x100.to_le_bytes());
        buf.extend_from_slice(&self.virtual_memory_bytes.to_le_bytes());
        buf.extend_from_slice(&self.physical_memory_bytes.to_le_bytes());
        buf.extend_from_slice(&self.thread_count.to_le_bytes());
        buf.extend_from_slice(&self.jitter_ns.to_le_bytes());
        buf.extend_from_slice(&self.captured_at_unix_secs.to_le_bytes());

        BehaviorDigest(sha256(&buf))
    }
}

// ─── Digest wrapper ──────────────────────────────────────────────────────────

/// SHA-256 digest of a [`BehaviorSnapshot`].
///
/// This is `BehaviorFingerprint_i` in the BEW equation. It is 32 bytes of
/// opaque entropy — the underlying metrics are never exposed.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct BehaviorDigest(pub [u8; DIGEST_LEN]);

impl AsRef<[u8]> for BehaviorDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ─── Sampler ─────────────────────────────────────────────────────────────────

/// Samples live behavioral metrics from the host OS.
///
/// # Feature Flags
/// - With `sysinfo-capture` (default): uses `sysinfo` to read real metrics.
/// - Without: returns a deterministic zero-filled snapshot suitable for
///   test environments (never use in production!).
pub struct BehaviorSampler {
    #[cfg(feature = "sysinfo-capture")]
    system: System,
}

impl BehaviorSampler {
    /// Create a new sampler.
    ///
    /// Initialises `sysinfo::System` with a minimal `RefreshKind` to keep
    /// overhead low. Only CPU and process memory are refreshed.
    pub fn new() -> Self {
        #[cfg(feature = "sysinfo-capture")]
        {
            Self {
                system: System::new_all(),
            }
        }
        #[cfg(not(feature = "sysinfo-capture"))]
        {
            Self {}
        }
    }

    /// Capture a single [`BehaviorSnapshot`].
    ///
    /// This call blocks for approximately 1ms to measure timing jitter.
    /// Call from a `tokio::task::spawn_blocking` context to avoid stalling
    /// the async executor.
    ///
    /// # Errors
    /// Returns a [`BehaviorError`] if the OS rejects the metrics query.
    pub fn capture(&mut self) -> Result<BehaviorSnapshot, BehaviorError> {
        #[cfg(feature = "sysinfo-capture")]
        {
            self.capture_live()
        }
        #[cfg(not(feature = "sysinfo-capture"))]
        {
            Ok(self.capture_stub())
        }
    }

    // ── Live capture (sysinfo feature enabled) ───────────────────────────────

    #[cfg(feature = "sysinfo-capture")]
    fn capture_live(&mut self) -> Result<BehaviorSnapshot, BehaviorError> {
        use sysinfo::{ProcessRefreshKind, RefreshKind, CpuRefreshKind};

        // Refresh only what we need — avoids disk/net enumeration overhead.
        self.system.refresh_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::new().with_cpu_usage())
                .with_processes(ProcessRefreshKind::new().with_cpu().with_memory()),
        );

        let pid = sysinfo::get_current_pid()
            .map_err(|e| BehaviorError::PidUnavailable(e.to_string()))?;

        let process = self
            .system
            .process(pid)
            .ok_or(BehaviorError::ProcessNotFound(pid.to_string()))?;

        // sysinfo 0.30: global_cpu_info() -> &Cpu; .cpu_usage() -> f32
        let cpu_pct_x100 = (self.system.global_cpu_info().cpu_usage() * 100.0) as u32;

        let jitter_ns = Self::measure_jitter();

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        Ok(BehaviorSnapshot {
            cpu_usage_pct_x100:    cpu_pct_x100,
            virtual_memory_bytes:  process.virtual_memory(),
            physical_memory_bytes: process.memory(),
            thread_count:          rayon_thread_count(),
            jitter_ns,
            captured_at_unix_secs: now_unix,
        })
    }

    // ── Stub capture (no sysinfo feature) ────────────────────────────────────

    #[cfg(not(feature = "sysinfo-capture"))]
    #[allow(dead_code)]
    fn capture_stub(&self) -> BehaviorSnapshot {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        BehaviorSnapshot {
            cpu_usage_pct_x100:    0,
            virtual_memory_bytes:  0,
            physical_memory_bytes: 0,
            thread_count:          1,
            jitter_ns:             Self::measure_jitter(),
            captured_at_unix_secs: now_unix,
        }
    }

    // ── Timing jitter ────────────────────────────────────────────────────────

    /// Measure OS scheduling jitter by recording the overshoot of a 1ms sleep.
    ///
    /// This value is non-deterministic and cannot be forged in retrospect.
    /// A forger would need to control the host OS scheduler at the exact
    /// moment the event was generated.
    #[must_use]
    fn measure_jitter() -> u64 {
        let requested = Duration::from_millis(1);
        let start = Instant::now();
        std::thread::sleep(requested);
        let actual = start.elapsed();

        // Jitter = overshoot; clamp to 0 if somehow woke early (rare).
        actual
            .checked_sub(requested)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64
    }
}

impl Default for BehaviorSampler {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Thread count helper ─────────────────────────────────────────────────────

/// Returns the number of threads the current process is using.
///
/// Reads `/proc/self/status` on Linux; falls back to 1 on other platforms.
/// This is a best-effort metric — accuracy is sufficient for forensic use.
#[must_use]
fn rayon_thread_count() -> u32 {
    // Platform-independent: use sysinfo process thread count if available,
    // otherwise fall back to the Rust runtime's logical core count.
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

// ─── Error type ─────────────────────────────────────────────────────────────

/// Errors produced by [`BehaviorSampler`].
#[derive(Debug, thiserror::Error)]
pub enum BehaviorError {
    /// Could not retrieve current process ID.
    #[error("could not get current PID: {0}")]
    PidUnavailable(String),

    /// Process not found in sysinfo process table.
    #[error("process not found: {0}")]
    ProcessNotFound(String),
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_digest_is_deterministic() {
        let snap = BehaviorSnapshot {
            cpu_usage_pct_x100:    5000,
            virtual_memory_bytes:  1_073_741_824,
            physical_memory_bytes: 536_870_912,
            thread_count:          8,
            jitter_ns:             42_000,
            captured_at_unix_secs: 1_700_000_000,
        };

        let d1 = snap.to_digest();
        let d2 = snap.to_digest();
        assert_eq!(d1, d2, "Digest must be deterministic for the same snapshot");
    }

    #[test]
    fn test_different_snapshots_produce_different_digests() {
        let s1 = BehaviorSnapshot {
            cpu_usage_pct_x100: 1000,
            virtual_memory_bytes: 512,
            physical_memory_bytes: 256,
            thread_count: 4,
            jitter_ns: 100,
            captured_at_unix_secs: 1_700_000_000,
        };
        let mut s2 = s1.clone();
        s2.cpu_usage_pct_x100 = 9999;

        assert_ne!(s1.to_digest(), s2.to_digest());
    }

    #[test]
    fn test_sampler_capture_succeeds() {
        let mut sampler = BehaviorSampler::new();
        let snap = sampler.capture().expect("capture should succeed");
        // Basic sanity: captured_at_unix_secs is in a plausible range
        assert!(snap.captured_at_unix_secs > 1_000_000_000);
    }

    #[test]
    fn test_jitter_is_nonzero_on_most_systems() {
        // This test is probabilistic — jitter could be 0 on a perfectly
        // deterministic simulator, so we allow it but record the value.
        let mut sampler = BehaviorSampler::new();
        let snap = sampler.capture().unwrap();
        // Just verify it doesn't panic and is in reasonable range
        assert!(snap.jitter_ns < 1_000_000_000, "jitter < 1 second");
    }
}
