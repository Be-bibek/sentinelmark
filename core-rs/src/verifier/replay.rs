//! # `replay` — Replay Attack Detection Engine
//!
//! Detects duplicate and delayed telemetry events using a sliding-window
//! timestamp and nonce cache.
//!
//! ## Invariants
//! - **Timestamp Window**: Rejects events older than `now - max_drift` or newer than `now + max_drift`.
//! - **Nonce Uniqueness**: Rejects events whose `nonce` has already been seen within the valid window.
//! - **Bounded Memory**: Automatically evicts nonces once their timestamp falls out of the valid window.

use crate::telemetry::{TelemetryEvent, NONCE_LEN};
use chrono::{DateTime, Duration, Utc};
use std::collections::{BTreeSet, HashSet};
use std::sync::Mutex;

// ─── Configuration ───────────────────────────────────────────────────────────

/// Configuration for the replay detector.
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Maximum allowed difference between server time and event time.
    /// Acts as both the future tolerance and the historical cache window.
    pub max_time_drift: Duration,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            max_time_drift: Duration::seconds(30),
        }
    }
}

// ─── Error Type ──────────────────────────────────────────────────────────────

/// Reasons for an event to be rejected by the replay detector.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplayError {
    /// The event is too old and falls outside the cache window.
    #[error("event expired (drift: {drift_ms}ms)")]
    Expired { 
        /// How far behind the current time the event is, in milliseconds.
        drift_ms: i64 
    },

    /// The event timestamp is too far in the future.
    #[error("event from the future (drift: {drift_ms}ms)")]
    Future { 
        /// How far ahead of the current time the event is, in milliseconds.
        drift_ms: i64 
    },

    /// The exact nonce has already been processed within the window.
    #[error("duplicate nonce detected")]
    DuplicateNonce,
}

// ─── Replay Detector ─────────────────────────────────────────────────────────

/// Internal state of the replay detector, wrapped in a Mutex for thread-safety.
struct ReplayState {
    /// Fast O(1) lookup for nonces currently in the window.
    seen_nonces: HashSet<[u8; NONCE_LEN]>,

    /// O(log N) ordered set for eagerly evicting expired nonces.
    /// Ordered by (Timestamp, Nonce).
    expiration_queue: BTreeSet<(DateTime<Utc>, [u8; NONCE_LEN])>,
}

/// The Replay Detection Engine.
///
/// Thread-safe and designed to be shared across async task workers.
pub struct ReplayDetector {
    config: ReplayConfig,
    state: Mutex<ReplayState>,
}

impl ReplayDetector {
    /// Create a new replay detector with the specified configuration.
    #[must_use]
    pub fn new(config: ReplayConfig) -> Self {
        Self {
            config,
            state: Mutex::new(ReplayState {
                seen_nonces: HashSet::new(),
                expiration_queue: BTreeSet::new(),
            }),
        }
    }

    /// Check if an event is a replay or violates timestamp invariants.
    ///
    /// If the event is valid, its nonce is recorded.
    /// Automatically evicts expired nonces from the cache.
    ///
    /// # Errors
    /// Returns [`ReplayError`] if the event is a replay, expired, or from the future.
    pub fn check_and_record(&self, event: &TelemetryEvent) -> Result<(), ReplayError> {
        let now = Utc::now();
        let event_time = event.captured_at;
        
        // Compute drift: positive means event is in the past, negative means event is in the future.
        let drift = now.signed_duration_since(event_time);
        
        // 1. Timestamp Validation
        if drift > self.config.max_time_drift {
            return Err(ReplayError::Expired { drift_ms: drift.num_milliseconds() });
        }
        
        if -drift > self.config.max_time_drift {
            return Err(ReplayError::Future { drift_ms: -drift.num_milliseconds() });
        }

        // 2. Lock State for Deduplication and Eviction
        let mut state = self.state.lock().expect("mutex poisoned");

        // 3. Eager Eviction of Old Nonces
        let cutoff_time = now - self.config.max_time_drift;
        
        // We can split the BTreeSet at the cutoff time. 
        // BTreeSet doesn't have an exact `drain_before` until nightly, so we iterate and pop.
        let mut to_remove = Vec::new();
        for &(ts, nonce) in state.expiration_queue.iter() {
            if ts < cutoff_time {
                to_remove.push((ts, nonce));
            } else {
                // Since the set is ordered by timestamp, we can stop at the first non-expired entry.
                break;
            }
        }

        for entry in to_remove {
            state.expiration_queue.remove(&entry);
            state.seen_nonces.remove(&entry.1);
        }

        // 4. Nonce Deduplication
        if state.seen_nonces.contains(&event.nonce) {
            return Err(ReplayError::DuplicateNonce);
        }

        // 5. Record Valid Nonce
        state.seen_nonces.insert(event.nonce);
        state.expiration_queue.insert((event_time, event.nonce));

        Ok(())
    }

    /// Returns the number of currently tracked nonces.
    /// Useful for telemetry and benchmarking.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        let state = self.state.lock().expect("mutex poisoned");
        state.seen_nonces.len()
    }
}

impl Default for ReplayDetector {
    fn default() -> Self {
        Self::new(ReplayConfig::default())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::HASH_LEN;

    fn make_event_at(time: DateTime<Utc>) -> TelemetryEvent {
        let mut e = TelemetryEvent::new(
            "device",
            [0u8; HASH_LEN],
            serde_json::json!({}),
        ).unwrap();
        e.captured_at = time;
        // Don't need to finalize for the replay check since it just reads captured_at and nonce
        e
    }

    #[test]
    fn test_valid_event_accepted() {
        let detector = ReplayDetector::default();
        let e = make_event_at(Utc::now());
        assert!(detector.check_and_record(&e).is_ok());
        assert_eq!(detector.tracked_count(), 1);
    }

    #[test]
    fn test_duplicate_nonce_rejected() {
        let detector = ReplayDetector::default();
        let e = make_event_at(Utc::now());
        
        assert!(detector.check_and_record(&e).is_ok());
        let res = detector.check_and_record(&e);
        assert_eq!(res, Err(ReplayError::DuplicateNonce));
        assert_eq!(detector.tracked_count(), 1);
    }

    #[test]
    fn test_expired_event_rejected() {
        let config = ReplayConfig { max_time_drift: Duration::seconds(5) };
        let detector = ReplayDetector::new(config);
        
        let e = make_event_at(Utc::now() - Duration::seconds(10));
        let res = detector.check_and_record(&e);
        assert!(matches!(res, Err(ReplayError::Expired { .. })));
    }

    #[test]
    fn test_future_event_rejected() {
        let config = ReplayConfig { max_time_drift: Duration::seconds(5) };
        let detector = ReplayDetector::new(config);
        
        let e = make_event_at(Utc::now() + Duration::seconds(10));
        let res = detector.check_and_record(&e);
        assert!(matches!(res, Err(ReplayError::Future { .. })));
    }

    #[test]
    fn test_automatic_eviction() {
        let config = ReplayConfig { max_time_drift: Duration::seconds(2) };
        let detector = ReplayDetector::new(config);
        
        // We simulate eviction by manually setting up the state 
        // with an old event, then passing a new valid event.
        let mut e1 = make_event_at(Utc::now() - Duration::seconds(3));
        let old_nonce = [0xaa; NONCE_LEN];
        e1.nonce = old_nonce;

        {
            let mut state = detector.state.lock().unwrap();
            state.seen_nonces.insert(old_nonce);
            state.expiration_queue.insert((e1.captured_at, old_nonce));
        }
        
        assert_eq!(detector.tracked_count(), 1);

        // Process a new valid event. This should trigger eviction of the old one.
        let e2 = make_event_at(Utc::now());
        assert!(detector.check_and_record(&e2).is_ok());

        // e1 should be gone, e2 should be present. Total count: 1.
        assert_eq!(detector.tracked_count(), 1);
        
        let state = detector.state.lock().unwrap();
        assert!(!state.seen_nonces.contains(&old_nonce));
    }
}
