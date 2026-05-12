//! # `transport` — Async Telemetry Transport Layer
//!
//! Provides a deterministic, resilient transport queue for forensic telemetry.
//!
//! ## Core Guarantees
//! - **Immutability**: Accepts only pre-serialized `ImmutableEnvelope`s. Prevents serialization drift during retries.
//! - **Bounded Concurrency**: Uses an mpsc queue to absorb latency without blocking application threads.
//! - **Deterministic Retries**: Exponential backoff for transient failures (timeouts, 5xx), immediate abort for permanent failures (4xx).

use crate::telemetry::{TelemetryEvent, TelemetryError};
use reqwest::{Client, StatusCode};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

// ─── Immutable Envelope ──────────────────────────────────────────────────────

/// An immutable, pre-serialized telemetry envelope.
///
/// Guaranteed to represent the exact bytes that will be sent over the wire.
/// By storing the pre-serialized form, we ensure that retries and queueing
/// do not accidentally alter timestamps, recompute hashes, or regenerate nonces.
#[derive(Debug, Clone)]
pub struct ImmutableEnvelope {
    event_id: String,
    payload: Vec<u8>,
}

impl ImmutableEnvelope {
    /// Construct an envelope from a finalized telemetry event.
    ///
    /// # Errors
    /// Returns [`TelemetryError::SerializationFailed`] if JSON serialization fails.
    pub fn new(event: &TelemetryEvent) -> Result<Self, TelemetryError> {
        let payload = event.canonical_bytes()
            .map_err(|e| TelemetryError::SerializationFailed(e.to_string()))?;
        
        Ok(Self {
            event_id: event.event_id.to_string(),
            payload,
        })
    }

    /// Access the raw serialized bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Access the event ID for tracing.
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
}

// ─── Configuration ───────────────────────────────────────────────────────────

/// Configuration for the async transport queue and retry policy.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Target verification endpoint (e.g., `https://api.prooftrace.com/ingest`).
    pub endpoint: String,
    
    /// Maximum number of envelopes to buffer in memory before blocking/dropping.
    pub queue_capacity: usize,
    
    /// Hard timeout per individual HTTP request.
    pub request_timeout: Duration,
    
    /// Maximum number of delivery attempts per envelope.
    pub max_retries: u32,
    
    /// Base delay for exponential backoff.
    pub base_backoff: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:8000/ingest".to_string(),
            queue_capacity: 10_000,
            request_timeout: Duration::from_secs(5),
            max_retries: 5,
            base_backoff: Duration::from_millis(500),
        }
    }
}

// ─── Error Type ──────────────────────────────────────────────────────────────

/// Transport layer errors.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The local in-memory transport queue is full.
    #[error("transport queue is at capacity")]
    QueueFull,

    /// Final delivery failed after exhausting all retries.
    #[error("delivery failed after exhausted retries: {0}")]
    DeliveryFailed(String),
}

// ─── Transport Queue ─────────────────────────────────────────────────────────

/// Resilient async telemetry dispatcher.
///
/// Use `clone()` to share the sender across multiple application threads.
#[derive(Clone)]
pub struct TransportClient {
    sender: mpsc::Sender<ImmutableEnvelope>,
}

impl TransportClient {
    /// Create a new transport client and spawn the background dispatcher task.
    ///
    /// The dispatcher will live as long as the tokio runtime and automatically
    /// tear down when all `TransportClient` instances are dropped.
    #[must_use]
    pub fn new(config: TransportConfig) -> Self {
        let (tx, rx) = mpsc::channel(config.queue_capacity);
        tokio::spawn(transport_worker(rx, config));
        Self { sender: tx }
    }

    /// Enqueue an immutable envelope for asynchronous delivery.
    ///
    /// This method is fast and non-blocking unless the queue is entirely full.
    ///
    /// # Errors
    /// Returns [`TransportError::QueueFull`] if the internal bounded channel is at capacity.
    pub async fn dispatch(&self, envelope: ImmutableEnvelope) -> Result<(), TransportError> {
        self.sender
            .send(envelope)
            .await
            .map_err(|_| TransportError::QueueFull)
    }
    
    /// Dispatch synchronously from a non-async context.
    ///
    /// # Errors
    /// Returns [`TransportError::QueueFull`] if at capacity.
    pub fn dispatch_sync(&self, envelope: ImmutableEnvelope) -> Result<(), TransportError> {
        self.sender
            .try_send(envelope)
            .map_err(|_| TransportError::QueueFull)
    }
}

// ─── Background Worker ───────────────────────────────────────────────────────

/// Background task that processes envelopes and enforces the retry policy.
async fn transport_worker(
    mut rx: mpsc::Receiver<ImmutableEnvelope>,
    config: TransportConfig,
) {
    let client = Client::builder()
        .timeout(config.request_timeout)
        .build()
        .expect("failed to construct reqwest client");

    while let Some(env) = rx.recv().await {
        let mut attempt = 0;
        let mut success = false;

        while attempt < config.max_retries {
            attempt += 1;

            let req = client
                .post(&config.endpoint)
                .header("Content-Type", "application/json")
                .body(env.payload.clone());

            match req.send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        info!(
                            event_id = %env.event_id,
                            attempt,
                            "telemetry delivered successfully"
                        );
                        success = true;
                        break;
                    } else if resp.status().is_server_error() || resp.status() == StatusCode::TOO_MANY_REQUESTS {
                        warn!(
                            event_id = %env.event_id,
                            status = %resp.status(),
                            attempt,
                            "transient error, retrying"
                        );
                    } else {
                        // 4xx errors (except 429) are permanent. Sending the exact same payload will persistently fail.
                        error!(
                            event_id = %env.event_id,
                            status = %resp.status(),
                            "permanent rejection, dropping telemetry"
                        );
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        event_id = %env.event_id,
                        error = %e,
                        attempt,
                        "network error, retrying"
                    );
                }
            }

            if attempt < config.max_retries {
                // Exponential backoff: base * 2^(attempt-1)
                let delay_ms = config.base_backoff.as_millis() as u64 * (1 << (attempt - 1));
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }

        if !success {
            error!(
                event_id = %env.event_id,
                "telemetry delivery fully failed after {} attempts",
                attempt
            );
        }
    }
}
