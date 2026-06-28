//! GET /metrics — Prometheus-compatible metrics

use axum::{extract::State, response::IntoResponse, http::StatusCode};
use crate::state::AppState;
use crate::ws::CONNECTED_CLIENTS;
use std::sync::atomic::Ordering;

pub async fn metrics(State(_state): State<AppState>) -> impl IntoResponse {
    let clients = CONNECTED_CLIENTS.load(Ordering::Relaxed);
    let body = format!(
        "# HELP sentinelmark_ws_connected_clients Number of active WebSocket clients\n\
        # TYPE sentinelmark_ws_connected_clients gauge\n\
        sentinelmark_ws_connected_clients {clients}\n"
    );
    (StatusCode::OK, [("content-type", "text/plain; version=0.0.4")], body)
}
