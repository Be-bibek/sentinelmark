//! WebSocket endpoint and typed event model.
//! Broadcasts structured trust events to all connected clients.

use axum::{
    extract::{State, WebSocketUpgrade},
    response::Response,
};
use axum::extract::ws::{WebSocket, Message};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use tokio::sync::broadcast;
use tracing::{info, warn};
use std::sync::atomic::{AtomicUsize, Ordering};
use crate::state::AppState;

/// Global count of connected WebSocket clients.
pub static CONNECTED_CLIENTS: AtomicUsize = AtomicUsize::new(0);

/// Strongly typed WebSocket event types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WsEvent {
    TrustEvaluated {
        user_id: String,
        trust_score: f64,
        risk_score: f64,
        decision: String,
        evaluation_time_ms: i64,
        timestamp: DateTime<Utc>,
    },
    TelemetryReceived {
        user_id: String,
        device_id: String,
        action_type: String,
        timestamp: DateTime<Utc>,
    },
    RiskChanged {
        user_id: String,
        previous_score: f64,
        new_score: f64,
        timestamp: DateTime<Utc>,
    },
    PolicyChanged {
        user_id: String,
        decision: String,
        requires_multi_sig: bool,
        timestamp: DateTime<Utc>,
    },
    AuditCreated {
        audit_id: Uuid,
        user_id: String,
        timestamp: DateTime<Utc>,
    },
    ProfileUpdated {
        user_id: String,
        timestamp: DateTime<Utc>,
    },
    SessionBlocked {
        user_id: String,
        reason: String,
        timestamp: DateTime<Utc>,
    },
    MultiSigRequired {
        user_id: String,
        risk_score: f64,
        timestamp: DateTime<Utc>,
    },
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state.ws_tx.subscribe()))
}

async fn handle_socket(mut socket: WebSocket, mut rx: broadcast::Receiver<WsEvent>) {
    CONNECTED_CLIENTS.fetch_add(1, Ordering::Relaxed);
    info!("WebSocket client connected. Total: {}", CONNECTED_CLIENTS.load(Ordering::Relaxed));

    // Send a welcome message
    let welcome = serde_json::json!({
        "event": "connected",
        "message": "SentinelMark WebSocket stream active",
        "timestamp": Utc::now().to_rfc3339()
    });
    if socket.send(Message::Text(welcome.to_string())).await.is_err() {
        CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
        return;
    }

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(evt) => {
                        let json = match serde_json::to_string(&evt) {
                            Ok(j) => j,
                            Err(e) => {
                                warn!("WS serialization error: {}", e);
                                continue;
                            }
                        };
                        if socket.send(Message::Text(json)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("WebSocket client lagged by {} messages", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            // Poll for client disconnect (ping/close frames)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        let _ = socket.send(Message::Pong(data)).await;
                    }
                    _ => {}
                }
            }
        }
    }

    CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
    info!("WebSocket client disconnected. Total: {}", CONNECTED_CLIENTS.load(Ordering::Relaxed));
}
