//! GET /metrics — Prometheus text exposition format
//! Scraped by Prometheus every 15s as configured in prometheus/prometheus.yml

use axum::response::IntoResponse;
use axum::http::StatusCode;
use crate::telemetry;

pub async fn metrics() -> impl IntoResponse {
    let body = telemetry::gather_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}
