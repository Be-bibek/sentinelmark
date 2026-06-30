//! Shared application state injected into all Axum handlers.

use crate::adapters::AdapterRegistry;
use crate::config::Config;
use crate::ws::WsEvent;
use sentinelmark_rs::SentinelMark;
use sqlx::PgPool;
use std::sync::Arc;
use storage_engine::PostgresStorage;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub storage: Arc<PostgresStorage>,
    pub sdk: Arc<SentinelMark>,
    pub ws_tx: broadcast::Sender<WsEvent>,
    pub registry: Arc<AdapterRegistry>,
}
