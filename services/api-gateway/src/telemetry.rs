//! Prometheus metrics registry for SentinelMark API Gateway.
//!
//! All metrics are registered here as module-level statics so they can be
//! incremented from anywhere in the codebase without threading AppState.

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_histogram_vec, CounterVec, Encoder, Gauge, HistogramVec,
    TextEncoder,
};

lazy_static! {
    /// Total HTTP requests served, partitioned by method, path, and status.
    pub static ref HTTP_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "sentinelmark_http_requests_total",
        "Total number of HTTP requests",
        &["method", "path", "status"]
    ).expect("metric registration failed");

    /// HTTP request latency histogram in seconds.
    pub static ref HTTP_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "sentinelmark_http_request_duration_seconds",
        "HTTP request latency in seconds",
        &["method", "path"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    ).expect("metric registration failed");

    /// Total Trust Engine evaluations, partitioned by decision and product.
    pub static ref TRUST_EVALUATIONS_TOTAL: CounterVec = register_counter_vec!(
        "sentinelmark_trust_evaluations_total",
        "Total number of trust engine evaluations",
        &["decision", "product_slug"]
    ).expect("metric registration failed");

    /// Trust Engine evaluation latency histogram in seconds.
    pub static ref TRUST_EVALUATION_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "sentinelmark_trust_evaluation_duration_seconds",
        "Trust Engine evaluation latency in seconds",
        &["product_slug"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    ).expect("metric registration failed");

    /// Currently connected WebSocket clients.
    pub static ref WS_CONNECTED_CLIENTS: Gauge = prometheus::register_gauge!(
        "sentinelmark_ws_connected_clients",
        "Number of active WebSocket clients"
    ).expect("metric registration failed");

    /// Total API authentication failures.
    pub static ref AUTH_FAILURES_TOTAL: CounterVec = register_counter_vec!(
        "sentinelmark_auth_failures_total",
        "Total authentication failures",
        &["reason"]
    ).expect("metric registration failed");

    /// Active DB pool connections.
    pub static ref DB_POOL_SIZE: Gauge = prometheus::register_gauge!(
        "sentinelmark_db_pool_size",
        "Number of active database pool connections"
    ).expect("metric registration failed");
}

/// Render all metrics in Prometheus text exposition format.
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .expect("metrics encoding failed");
    String::from_utf8(buffer).expect("metrics utf8 encoding failed")
}
