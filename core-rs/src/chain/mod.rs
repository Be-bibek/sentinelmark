//! # `chain` — Event Hash Chain Manager
//!
//! Implements a tamper-evident append-only chain where each event commits
//! to the SHA-256 hash of all prior events. Deletion, reordering, or
//! modification of any event breaks the chain and is immediately detectable.
//!
//! ## Chain Integrity Invariant
//! For any valid chain `[E_0, E_1, ..., E_n]`:
//! ```text
//! E_0.prev_hash == [0u8; 32]                     (genesis)
//! E_i.prev_hash == E_{i-1}.current_hash          (i > 0)
//! E_i.current_hash == SHA-256(canonical(E_i))    (self-consistency)
//! ```
//!
//! ## Security Properties
//! - **Tamper evidence**: any field modification changes `current_hash`.
//! - **Insertion detection**: a forged event inserted between two real events
//!   will have `prev_hash != E_{i-1}.current_hash`.
//! - **Replay detection**: combined with nonce and timestamp checks in `verifier`.

use crate::crypto::{ct_bytes_eq, sha256};
use crate::telemetry::{TelemetryEvent, HASH_LEN};

// ─── Genesis Hash ────────────────────────────────────────────────────────────

/// The `prev_hash` of the first event in a chain.
/// Must be `[0u8; 32]` — verified by the chain manager.
pub const GENESIS_HASH: [u8; HASH_LEN] = [0u8; HASH_LEN];

// ─── Chain Manager ───────────────────────────────────────────────────────────

/// Manages the append-only event chain.
///
/// Maintains the current chain tip hash (`last_hash`). Each new event's
/// `prev_hash` must match `last_hash` before it is accepted.
///
/// Thread-safety: wrap in `Arc<tokio::sync::Mutex<ChainManager>>` for shared use.
pub struct ChainManager {
    last_hash: [u8; HASH_LEN],
    event_count: u64,
}

impl ChainManager {
    /// Create a new chain starting from genesis.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_hash: GENESIS_HASH,
            event_count: 0,
        }
    }

    /// Return the current chain tip hash.
    #[must_use]
    pub fn last_hash(&self) -> &[u8; HASH_LEN] {
        &self.last_hash
    }

    /// Return the number of events accepted so far.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Append a finalized event to the chain.
    ///
    /// # Errors
    /// - `ChainError::PrevHashMismatch` if `event.prev_hash != self.last_hash`
    /// - `ChainError::HashInconsistent` if `event.current_hash` doesn't match
    ///   the SHA-256 of the event's canonical form
    pub fn append(&mut self, event: &TelemetryEvent) -> Result<(), ChainError> {
        // Verify prev_hash links correctly (constant-time)
        if !ct_bytes_eq(&event.prev_hash, &self.last_hash) {
            return Err(ChainError::PrevHashMismatch {
                expected: hex::encode(&self.last_hash),
                got: hex::encode(&event.prev_hash),
            });
        }

        // Verify self-consistency of current_hash using the pre-image
        let preimage = event
            .preimage_bytes()
            .map_err(|e| ChainError::SerializationFailed(e.to_string()))?;
        let expected_hash = sha256(&preimage);

        if !ct_bytes_eq(&event.current_hash, &expected_hash) {
            return Err(ChainError::HashInconsistent {
                event_id: event.event_id.to_string(),
            });
        }

        self.last_hash = event.current_hash;
        self.event_count += 1;
        Ok(())
    }

    /// Verify an entire chain of events without updating state.
    ///
    /// Use for forensic validation of a collected event log.
    pub fn verify_chain(events: &[TelemetryEvent]) -> Result<(), ChainError> {
        if events.is_empty() {
            return Ok(());
        }

        let mut expected_prev = GENESIS_HASH;

        for (i, event) in events.iter().enumerate() {
            if !ct_bytes_eq(&event.prev_hash, &expected_prev) {
                return Err(ChainError::PrevHashMismatch {
                    expected: hex::encode(&expected_prev),
                    got: hex::encode(&event.prev_hash),
                });
            }

            let preimage = event.preimage_bytes()
                .map_err(|e| ChainError::SerializationFailed(e.to_string()))?;
            let computed_hash = sha256(&preimage);

            if !ct_bytes_eq(&event.current_hash, &computed_hash) {
                return Err(ChainError::HashInconsistentAt {
                    index: i,
                    event_id: event.event_id.to_string(),
                });
            }

            expected_prev = event.current_hash;
        }

        Ok(())
    }
}

impl Default for ChainManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Error type ─────────────────────────────────────────────────────────────

/// Errors produced by chain operations.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The event's `prev_hash` does not match the chain tip.
    #[error("prev_hash mismatch: expected {expected}, got {got}")]
    PrevHashMismatch {
        /// The hash we expected (chain tip).
        expected: String,
        /// The hash actually present in the event.
        got: String,
    },

    /// The event's `current_hash` is inconsistent with its content.
    #[error("current_hash inconsistent for event {event_id}")]
    HashInconsistent {
        /// UUID of the inconsistent event.
        event_id: String,
    },

    /// Hash inconsistent at a specific index during batch verification.
    #[error("hash inconsistent at index {index} (event {event_id})")]
    HashInconsistentAt {
        /// Zero-based index of the offending event in the batch.
        index: usize,
        /// UUID of the inconsistent event.
        event_id: String,
    },

    /// Canonical serialization failed during chain verification.
    #[error("serialization failed during chain verification: {0}")]
    SerializationFailed(String),
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{TelemetryEvent, WATERMARK_LEN, HASH_LEN};

    fn make_finalized_event(prev_hash: [u8; HASH_LEN]) -> TelemetryEvent {
        let mut e = TelemetryEvent::new(
            "test-device",
            prev_hash,
            serde_json::json!({"seq": 1}),
        ).unwrap();
        e.set_watermark([0xaa_u8; WATERMARK_LEN]);
        e.finalize().unwrap();
        e
    }

    #[test]
    fn test_chain_append_genesis() {
        let mut chain = ChainManager::new();
        let e = make_finalized_event(GENESIS_HASH);
        assert!(chain.append(&e).is_ok());
        assert_eq!(chain.event_count(), 1);
    }

    #[test]
    fn test_chain_append_linked() {
        let mut chain = ChainManager::new();
        let e1 = make_finalized_event(GENESIS_HASH);
        let e1_hash = e1.current_hash;
        chain.append(&e1).unwrap();

        let e2 = make_finalized_event(e1_hash);
        assert!(chain.append(&e2).is_ok());
        assert_eq!(chain.event_count(), 2);
    }

    #[test]
    fn test_chain_rejects_wrong_prev_hash() {
        let mut chain = ChainManager::new();
        let e = make_finalized_event([0xff_u8; HASH_LEN]); // wrong prev_hash
        let result = chain.append(&e);
        assert!(matches!(result, Err(ChainError::PrevHashMismatch { .. })));
    }

    #[test]
    fn test_full_chain_verification() {
        let e1 = make_finalized_event(GENESIS_HASH);
        let e2 = make_finalized_event(e1.current_hash);
        let e3 = make_finalized_event(e2.current_hash);

        let chain = vec![e1, e2, e3];
        assert!(ChainManager::verify_chain(&chain).is_ok());
    }

    #[test]
    fn test_tampered_event_detected() {
        let e1 = make_finalized_event(GENESIS_HASH);
        let mut e2 = make_finalized_event(e1.current_hash);
        // Tamper with payload without updating current_hash
        e2.watermark = [0x00_u8; WATERMARK_LEN]; // mutate without re-finalizing

        let chain = vec![e1, e2];
        let result = ChainManager::verify_chain(&chain);
        assert!(result.is_err());
    }
}
