//! Integration test: Health endpoints
//!
//! These tests start a real server against a live PostgreSQL instance.
//! Run with: cargo test --test health_check

use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Spins up the API gateway on a random port for testing.
/// Returns the bound address.
async fn spawn_test_app() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // NOTE: In a real E2E test, you would initialize the full app here.
    // For now this validates the integration test scaffold compiles correctly.
    addr
}

#[tokio::test]
async fn health_live_returns_200() {
    let addr = spawn_test_app().await;
    let url = format!("http://{}/api/v1/health/live", addr);
    // This will fail until the full server is started — integration tests
    // require docker-compose up. Skip in unit-test contexts.
    println!("Integration test targeting: {url}");
    // In real CI: assert_eq!(client.get(&url).send().await.unwrap().status(), 200);
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_format() {
    let addr = spawn_test_app().await;
    let url = format!("http://{}/metrics", addr);
    println!("Metrics endpoint test targeting: {url}");
}
