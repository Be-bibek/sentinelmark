#![allow(clippy::type_complexity)]

mod config;
mod error;
mod response;
mod state;
mod ws;
mod middleware;
mod routes;
mod adapters;
mod docs;
mod telemetry;


use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::signal;
use axum::{
    Router,
    routing::{get, post},
};
use tower_http::{
    cors::{CorsLayer, Any},
    trace::TraceLayer,
    timeout::TimeoutLayer,
    compression::CompressionLayer,
    request_id::{SetRequestIdLayer, PropagateRequestIdLayer},
};
use axum::http::{HeaderName, Method};
use std::time::Duration;
use tracing::{info, error};
use sqlx::postgres::PgPoolOptions;

use crate::config::Config;
use crate::state::AppState;
use crate::middleware::request_id::MakeUuidRequestId;
use crate::ws::{ws_handler, WsEvent};
use storage_engine::PostgresStorage;
use sentinelmark_rs::SentinelMark;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[tokio::main]
async fn main() {
    // ──────────────────────────────────────────────────────────────────────
    // 1. Load configuration — fail fast if invalid
    // ──────────────────────────────────────────────────────────────────────
    let config = Config::from_env().unwrap_or_else(|e| {
        eprintln!("FATAL: Configuration error: {e}");
        std::process::exit(1);
    });

    // ──────────────────────────────────────────────────────────────────────
    // 2. Initialize structured tracing
    // ──────────────────────────────────────────────────────────────────────
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.rust_log));

    if config.is_production() {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .pretty()
            .with_env_filter(env_filter)
            .init();
    }

    info!(
        version = "2.0.0",
        environment = ?config.environment,
        port = config.port,
        auth_mode = ?config.auth_mode,
        "SentinelMark v2 API Gateway starting"
    );

    // ──────────────────────────────────────────────────────────────────────
    // 2b. Initialize Prometheus metrics (force lazy_static init)
    // ──────────────────────────────────────────────────────────────────────
    lazy_static::initialize(&telemetry::HTTP_REQUESTS_TOTAL);
    lazy_static::initialize(&telemetry::TRUST_EVALUATIONS_TOTAL);
    lazy_static::initialize(&telemetry::WS_CONNECTED_CLIENTS);
    info!("Prometheus metrics registry initialized");

    // ──────────────────────────────────────────────────────────────────────
    // 3. Connect to PostgreSQL with retry
    // ──────────────────────────────────────────────────────────────────────
    let pool = connect_with_retry(&config.database_url, 5).await;

    // ──────────────────────────────────────────────────────────────────────
    // 4. Run database migrations automatically
    // ──────────────────────────────────────────────────────────────────────
    info!("Running database migrations...");
    // Migrations are embedded at compile time from the workspace /migrations directory.
    // Using sqlx::migrate::Migrator directly with path works at runtime.
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .unwrap_or_else(|e| {
            error!("Migration failed: {e}");
            std::process::exit(1);
        });
    info!("Database migrations complete");

    // ──────────────────────────────────────────────────────────────────────
    // 5. Initialize WebSocket broadcast channel
    // ──────────────────────────────────────────────────────────────────────
    let (ws_tx, _) = broadcast::channel::<WsEvent>(256);

    // ──────────────────────────────────────────────────────────────────────
    // 6. Build application state
    // ──────────────────────────────────────────────────────────────────────
    let storage = Arc::new(PostgresStorage::new(pool.clone()));
    let sdk = Arc::new(SentinelMark::new());
    let config = Arc::new(config);
    let registry = Arc::new(crate::adapters::AdapterRegistry::new());

    let state = AppState {
        config: config.clone(),
        db: pool,
        storage,
        sdk,
        ws_tx,
        registry,
    };

    // ──────────────────────────────────────────────────────────────────────
    // 7. Build CORS layer
    // ──────────────────────────────────────────────────────────────────────
    let allowed_origins: Vec<_> = config
        .cors_allowed_origins
        .iter()
        .filter_map(|o| o.parse::<axum::http::HeaderValue>().ok())
        .collect();

    let cors = if allowed_origins.is_empty() {
        CorsLayer::new().allow_methods(Any).allow_headers(Any)
    } else {
        CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(Any)
            .allow_origin(allowed_origins)
    };

    // ──────────────────────────────────────────────────────────────────────
    // 8. Build router
    // ──────────────────────────────────────────────────────────────────────
    let x_request_id = HeaderName::from_static("x-request-id");

    let api_v1_public = Router::new()
        // Health & infra — no auth required (Railway uses these for uptime checks)
        .route("/health/live",  get(routes::health::health_live))
        .route("/health/ready", get(routes::health::health_ready))
        .route("/version",      get(routes::version::version))
        .route("/metrics",      get(routes::metrics::metrics))
        .with_state(state.clone());

    let api_v1_protected = Router::new()
        // Core API — all require a valid API key
        .route("/evaluate",                  post(routes::evaluate::evaluate))
        .route("/telemetry",                 post(routes::telemetry::ingest_telemetry))
        .route("/behavior-profile/:user_id", get(routes::behavior_profile::get_behavior_profile))
        .route("/audit/:user_id",            get(routes::audit::get_audit))
        .route("/events",                    post(routes::events::handle_platform_event))
        
        // Developer Portal APIs
        .route("/api-keys",                  get(routes::api_keys::list_keys).post(routes::api_keys::create_key))
        .route("/api-keys/:id",              axum::routing::delete(routes::api_keys::revoke_key))
        .route("/events-explorer",           get(routes::events_explorer::list_events))
        .route("/products",                  get(routes::products::list_products))
        .route("/products/:product_slug/toggle", post(routes::products::toggle_product))
        .route("/projects/current",          get(routes::projects::get_project))
        .route("/team",                      get(routes::team::list_team))
        .route("/organizations/current",     get(routes::tenants::get_tenant))
        .route("/usage",                     get(routes::usage::get_usage_metrics))
        // WebSocket
        .route("/ws", get(ws_handler))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::auth::auth_middleware,
        ))
        .with_state(state);

    let api_v1 = api_v1_public.merge(api_v1_protected);

    let api_doc = crate::docs::ApiDoc::openapi();

    let app = Router::new()
        .nest("/api/v1", api_v1)
        .merge(SwaggerUi::new("/swagger-ui").url("/api/v1/openapi.json", api_doc))
        // Fallback for bare /health for Railway healthchecks
        .route("/health", get(|| async { "ok" }))
        .layer(SetRequestIdLayer::new(x_request_id.clone(), MakeUuidRequestId))
        .layer(PropagateRequestIdLayer::new(x_request_id))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(cors);

    // ──────────────────────────────────────────────────────────────────────
    // 9. Bind and serve with graceful shutdown
    // ──────────────────────────────────────────────────────────────────────
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!("Failed to bind to {addr}: {e}");
        std::process::exit(1);
    });

    info!("SentinelMark v2 listening on http://{addr}");
    info!("  → API:     http://{addr}/api/v1/health/live");
    info!("  → WS:      ws://{addr}/api/v1/ws");
    info!("  → Metrics: http://{addr}/metrics");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|e| {
            error!("Server error: {e}");
            std::process::exit(1);
        });

    info!("SentinelMark v2 shut down gracefully");
}

/// Retry connecting to PostgreSQL with exponential backoff.
async fn connect_with_retry(database_url: &str, max_retries: u32) -> sqlx::PgPool {
    let mut attempts = 0;
    loop {
        match PgPoolOptions::new()
            .max_connections(20)
            .min_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await
        {
            Ok(pool) => {
                info!("PostgreSQL connected successfully");
                return pool;
            }
            Err(e) => {
                attempts += 1;
                if attempts >= max_retries {
                    error!("Failed to connect to PostgreSQL after {max_retries} attempts: {e}");
                    std::process::exit(1);
                }
                let delay = Duration::from_secs(2u64.pow(attempts));
                error!("PostgreSQL connection attempt {attempts}/{max_retries} failed: {e}. Retrying in {delay:?}...");
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Graceful shutdown: waits for CTRL+C or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install CTRL+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received CTRL+C, shutting down"),
        _ = terminate => info!("Received SIGTERM, shutting down"),
    }
}
