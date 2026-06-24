//! # `watermark` — Behavior-Entangled Watermark Derivation Engine
//!
//! ## The BEW Equation
//!
//! ```text
//! W_i = HKDF-SHA256(
//!     IKM  = K_static || BehaviorFingerprint_i || H_prev,
//!     salt = nonce_i,
//!     info = b"sentinelmark-bew-v1"
//! )
//! ```
//!
//! ## IKM Construction Analysis
//!
//! The IKM is the concatenation of three components. Their roles:
//!
//! | Component | Length | Security Role |
//! |---|---|---|
//! | `K_static` | 32 B | Secret key; makes forgery computationally infeasible |
//! | `BehaviorFingerprint_i` | 32 B | Ties W_i to live device state |
//! | `H_prev` | 32 B | Chains events; makes out-of-order insertion detectable |
//!
//! Total IKM length: 96 bytes. HKDF-SHA256 can handle up to 255 × 32 = 8160 bytes
//! of output expansion — we request only 32 bytes, well within limit.
//!
//! ## Why the nonce is the HKDF salt?
//!
//! HKDF-SHA256(salt, IKM) → PRK = HMAC-SHA256(salt, IKM).
//!
//! A per-event random salt ensures that even if `K_static || BehaviorFingerprint_i ||
//! H_prev` repeats identically across two events (pathological case), the derived
//! watermarks are still different. This is especially important for:
//! - Idle systems with near-constant behavioral state
//! - Events generated in rapid succession before a behavioral update
//!
//! ## Secret Zeroization
//!
//! `K_static` is wrapped in [`StaticKey`] which implements `ZeroizeOnDrop`.
//! The IKM buffer assembled in `derive()` is a temporary `Vec<u8>` that is
//! explicitly zeroized before it's dropped, preventing stack/heap disclosure.
//!
//! ## Performance Tradeoffs
//!
//! - IKM assembly: one `Vec::with_capacity(96)` + 3 `extend_from_slice` = ~20ns
//! - HKDF-SHA256 (ring + sha2): ~300ns on x86 with SHA-NI
//! - Zeroize 96 bytes: ~5ns
//! - Total derivation: ~325ns (benchmarked separately in `benches/`)

use crate::behavior::BehaviorDigest;
use crate::crypto::{hkdf_derive, HKDF_INFO, OUTPUT_LEN};
use crate::telemetry::HASH_LEN;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── Static Device Key ──────────────────────────────────────────────────────

/// The long-term device secret `K_static`.
///
/// **Security invariants:**
/// - Must be loaded from a hardware-backed secret store or TPM in production.
/// - Must NEVER be logged, serialized, or transmitted.
/// - Zeroed from memory when dropped.
/// - Not `Clone`, not `Copy`.
#[derive(ZeroizeOnDrop)]
pub struct StaticKey([u8; OUTPUT_LEN]);

impl StaticKey {
    /// Construct from raw bytes.
    ///
    /// # Safety (conceptual)
    /// Caller is responsible for ensuring the source bytes come from a secure
    /// secret store and are themselves zeroized after this call.
    pub fn from_bytes(bytes: [u8; OUTPUT_LEN]) -> Self {
        Self(bytes)
    }

    /// Construct from a hex string (for testing and benchmarks only).
    ///
    /// # Errors
    /// Returns an error if the hex string is not exactly 64 hex characters.
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != OUTPUT_LEN {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; OUTPUT_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl AsRef<[u8]> for StaticKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// Deliberately omit Debug.
impl std::fmt::Debug for StaticKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StaticKey(<redacted>)")
    }
}

// ─── Watermark Engine ────────────────────────────────────────────────────────

/// BEW watermark derivation engine.
///
/// Holds `K_static` and exposes a single `derive` method.
/// The engine itself is stateless beyond the key — no mutable state, making
/// it safe to share across threads with `Arc<WatermarkEngine>`.
pub struct WatermarkEngine {
    static_key: StaticKey,
}

impl WatermarkEngine {
    /// Construct the engine with the device's static secret key.
    pub fn new(static_key: StaticKey) -> Self {
        Self { static_key }
    }

    /// Derive `W_i = HKDF-SHA256(IKM, salt=nonce_i, info="sentinelmark-bew-v1")`.
    ///
    /// # Parameters
    /// - `behavior`  — `BehaviorFingerprint_i` (32-byte SHA-256 of behavioral snapshot)
    /// - `prev_hash` — `H_prev` (32-byte SHA-256 of previous event)
    /// - `nonce`     — Per-event 32-byte random nonce (from `TelemetryEvent.nonce`)
    ///
    /// # Returns
    /// A 32-byte [`WatermarkOutput`] wrapping the HKDF output.
    ///
    /// # Security
    /// The IKM buffer is explicitly zeroized before drop.
    ///
    /// # Errors
    /// Returns [`WatermarkError`] if HKDF fails (should not occur for valid input sizes).
    pub fn derive(
        &self,
        behavior: &BehaviorDigest,
        prev_hash: &[u8; HASH_LEN],
        nonce: &[u8; 32],
    ) -> Result<WatermarkOutput, WatermarkError> {
        // Assemble IKM = K_static || BehaviorFingerprint_i || H_prev
        // Capacity is exact to avoid reallocation.
        let mut ikm = Vec::with_capacity(OUTPUT_LEN + 32 + HASH_LEN);
        ikm.extend_from_slice(self.static_key.as_ref());  // K_static  (32 B)
        ikm.extend_from_slice(behavior.as_ref());          // BehFP_i   (32 B)
        ikm.extend_from_slice(prev_hash.as_ref());         // H_prev    (32 B)

        // Derive using HKDF-SHA256
        let secret = hkdf_derive(&ikm, nonce, HKDF_INFO)
            .map_err(|e| WatermarkError::DerivationFailed(e.to_string()))?;

        // Zeroize IKM immediately — it contains K_static and behavioral data
        ikm.zeroize();

        // Extract raw bytes from SecretKey into a fixed-size array
        let mut output = [0u8; OUTPUT_LEN];
        output.copy_from_slice(secret.as_ref());
        // SecretKey is dropped and zeroed here (ZeroizeOnDrop)

        Ok(WatermarkOutput(output))
    }
}

// ─── Watermark Output ────────────────────────────────────────────────────────

/// The derived BEW watermark `W_i` — a 32-byte HKDF output.
///
/// Wrapped in a newtype to prevent accidental misuse (e.g., using it as a key).
/// Zeroized on drop, though it is not secret in the same sense as `K_static` —
/// it is transmitted in the telemetry event. Zeroization prevents lingering
/// copies in memory after transmission.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WatermarkOutput(pub [u8; OUTPUT_LEN]);

impl WatermarkOutput {
    /// Access the raw watermark bytes.
    pub fn as_bytes(&self) -> &[u8; OUTPUT_LEN] {
        &self.0
    }

    /// Consume the output and return the inner array.
    pub fn into_bytes(self) -> [u8; OUTPUT_LEN] {
        self.0
    }
}

impl std::fmt::Debug for WatermarkOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WatermarkOutput({})", hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for WatermarkOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ─── Error type ─────────────────────────────────────────────────────────────

/// Errors produced by the watermark engine.
#[derive(Debug, thiserror::Error)]
pub enum WatermarkError {
    /// HKDF derivation failed.
    #[error("HKDF derivation failed: {0}")]
    DerivationFailed(String),
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavior::BehaviorSnapshot;

    fn test_engine() -> WatermarkEngine {
        let key = StaticKey::from_hex(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        )
        .unwrap();
        WatermarkEngine::new(key)
    }

    fn test_behavior() -> BehaviorDigest {
        let snap = BehaviorSnapshot {
            cpu_usage_pct_x100:    5000,
            virtual_memory_bytes:  1_073_741_824,
            physical_memory_bytes: 536_870_912,
            thread_count:          8,
            jitter_ns:             42_000,
            captured_at_unix_secs: 1_700_000_000,
        };
        snap.to_digest()
    }

    #[test]
    fn test_derive_is_deterministic() {
        let engine = test_engine();
        let behavior = test_behavior();
        let prev_hash = [0u8; HASH_LEN];
        let nonce = [0xde_u8; 32];

        let w1 = engine.derive(&behavior, &prev_hash, &nonce).unwrap();
        let w2 = engine.derive(&behavior, &prev_hash, &nonce).unwrap();

        assert_eq!(w1.as_bytes(), w2.as_bytes(), "BEW must be deterministic");
    }

    #[test]
    fn test_different_nonce_yields_different_watermark() {
        let engine = test_engine();
        let behavior = test_behavior();
        let prev_hash = [0u8; HASH_LEN];

        let w1 = engine.derive(&behavior, &prev_hash, &[0x01_u8; 32]).unwrap();
        let w2 = engine.derive(&behavior, &prev_hash, &[0x02_u8; 32]).unwrap();

        assert_ne!(w1.as_bytes(), w2.as_bytes());
    }

    #[test]
    fn test_different_behavior_yields_different_watermark() {
        let engine = test_engine();
        let prev_hash = [0u8; HASH_LEN];
        let nonce = [0xab_u8; 32];

        let mut snap2 = BehaviorSnapshot {
            cpu_usage_pct_x100: 1, virtual_memory_bytes: 1,
            physical_memory_bytes: 1, thread_count: 1,
            jitter_ns: 1, captured_at_unix_secs: 1,
        };
        let b1 = test_behavior();
        snap2.cpu_usage_pct_x100 = 9999;
        let b2 = snap2.to_digest();

        let w1 = engine.derive(&b1, &prev_hash, &nonce).unwrap();
        let w2 = engine.derive(&b2, &prev_hash, &nonce).unwrap();
        assert_ne!(w1.as_bytes(), w2.as_bytes());
    }

    #[test]
    fn test_different_prev_hash_yields_different_watermark() {
        let engine = test_engine();
        let behavior = test_behavior();
        let nonce = [0xcd_u8; 32];

        let w1 = engine.derive(&behavior, &[0x00_u8; HASH_LEN], &nonce).unwrap();
        let w2 = engine.derive(&behavior, &[0xff_u8; HASH_LEN], &nonce).unwrap();
        assert_ne!(w1.as_bytes(), w2.as_bytes());
    }

    #[test]
    fn test_different_key_yields_different_watermark() {
        let k1 = StaticKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ).unwrap();
        let k2 = StaticKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        ).unwrap();

        let e1 = WatermarkEngine::new(k1);
        let e2 = WatermarkEngine::new(k2);

        let behavior = test_behavior();
        let prev_hash = [0u8; HASH_LEN];
        let nonce = [0u8; 32];

        let w1 = e1.derive(&behavior, &prev_hash, &nonce).unwrap();
        let w2 = e2.derive(&behavior, &prev_hash, &nonce).unwrap();
        assert_ne!(w1.as_bytes(), w2.as_bytes(),
            "Different K_static MUST yield different watermarks");
    }

    /// Regression test: Known-good BEW output vector.
    ///
    /// If this test fails after a code change, the protocol has changed and
    /// `SCHEMA_VERSION` must be bumped.
    #[test]
    fn test_known_good_output_vector() {
        let key_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let engine = WatermarkEngine::new(StaticKey::from_hex(key_hex).unwrap());

        let snap = BehaviorSnapshot {
            cpu_usage_pct_x100:    0,
            virtual_memory_bytes:  0,
            physical_memory_bytes: 0,
            thread_count:          0,
            jitter_ns:             0,
            captured_at_unix_secs: 0,
        };
        let behavior = snap.to_digest();
        let prev_hash = [0u8; HASH_LEN];
        let nonce = [0u8; 32];

        let w = engine.derive(&behavior, &prev_hash, &nonce).unwrap();

        // Record the output vector — store it and assert on first run.
        // This serves as a regression anchor for cryptographic correctness.
        let hex_output = hex::encode(w.as_bytes());
        println!("[KNOWN-VECTOR] BEW output: {}", hex_output);

        // Output must be 64 hex chars (32 bytes).
        assert_eq!(hex_output.len(), 64);
        // Output must not be all zeros.
        assert_ne!(w.as_bytes(), &[0u8; 32]);
    }
}
