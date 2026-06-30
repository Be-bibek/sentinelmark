//! GET /metrics — Prometheus text exposition format
//! Scraped by Prometheus every 15s as configured in prometheus/prometheus.yml

use crate::telemetry;
use axum::http::StatusCode;
use axum::response::IntoResponse;

pub async fn metrics() -> impl IntoResponse {
    let body = telemetry::gather_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}
