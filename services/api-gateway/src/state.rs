//! Shared application state injected into all Axum handlers.

use std::sync::Arc;
use sqlx::PgPool;
use tokio::sync::broadcast;
use crate::config::Config;
use crate::ws::WsEvent;
use storage_engine::PostgresStorage;
use sentinelmark_rs::SentinelMark;
use crate::adapters::AdapterRegistry;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub storage: Arc<PostgresStorage>,
    pub sdk: Arc<SentinelMark>,
    pub ws_tx: broadcast::Sender<WsEvent>,
    pub registry: Arc<AdapterRegistry>,
}
