//! POST /api/v1/evaluate — Full trust evaluation pipeline.
//!
//! Executes: Telemetry → Behavior → Risk → Trust → Policy → Audit → WS Broadcast

use axum::{extract::State, Json, http::HeaderMap};
use serde::{Deserialize, Serialize};
use chrono::Utc;
use std::time::Instant;
use tracing::{info, instrument};
use validator::Validate;

use crate::{error::AppError, response::ApiResponse, state::AppState, telemetry};
use crate::ws::WsEvent;

use sentinelmark_core::UserId;
use telemetry_engine::{TelemetryEvent, ActionType};
use audit_engine::AuditEntry;
use storage_engine::{ProfileRepository, AuditRepository, TelemetryRepository, TelemetryRow};
use sentinelmark_rs::EvaluationResult;

#[derive(Debug, Deserialize, Validate)]
pub struct EvaluateRequest {
    #[validate(length(min = 1, message = "user_id cannot be empty"))]
    pub user_id: String,
    pub event: TelemetryEventInput,
}

#[derive(Debug, Deserialize, Validate)]
pub struct TelemetryEventInput {
    #[validate(length(min = 1, message = "device_id cannot be empty"))]
    pub device_id: String,
    pub browser_fingerprint: String,
    #[validate(length(min = 7, message = "ip_address must be a valid IP"))]
    pub ip_address: String,
    pub geo_region: String,
    pub action_type: String,
    #[validate(range(min = 0.0, message = "transaction_amount must be non-negative"))]
    pub transaction_amount: Option<f64>,
    pub session_duration_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct EvaluateResponse {
    pub user_id: String,
    pub risk_score: f64,
    pub trust_score: f64,
    pub decision: String,
    pub requires_multi_sig: bool,
    pub risk_factors: Vec<String>,
    pub explanation: String,
    pub audit_id: Option<String>,
}

#[instrument(skip_all, fields(user_id = %payload.user_id))]
pub async fn evaluate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<EvaluateRequest>,
) -> Result<ApiResponse<EvaluateResponse>, AppError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Validate input
    payload.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    let user_id = UserId(payload.user_id.clone());
    let start = Instant::now();

    // Ensure the user exists in the database
    state.storage.ensure_user(&user_id).await?;

    // Fetch or create the behavior profile from PostgreSQL
    let profile = state
        .storage
        .get_profile(&user_id)
        .await?
        .unwrap_or_default();

    // Parse action type
    let action_type = parse_action_type(&payload.event.action_type);

    let event = TelemetryEvent {
        user_id: user_id.clone(),
        timestamp: Utc::now(),
        device_id: sentinelmark_core::DeviceId(payload.event.device_id.clone()),
        browser_fingerprint: payload.event.browser_fingerprint.clone(),
        ip_address: payload.event.ip_address.clone(),
        geo_region: payload.event.geo_region.clone(),
        action_type,
        transaction_amount: payload.event.transaction_amount,
        session_duration_secs: payload.event.session_duration_secs,
    };

    // Persist telemetry event
    let telemetry_row = TelemetryRow {
        device_id: payload.event.device_id.clone(),
        browser_fingerprint: payload.event.browser_fingerprint.clone(),
        ip_address: payload.event.ip_address.clone(),
        geo_region: payload.event.geo_region.clone(),
        action_type: payload.event.action_type.clone(),
        transaction_amount: payload.event.transaction_amount,
        session_duration_secs: payload.event.session_duration_secs.map(|v| v as i64),
        recorded_at: Utc::now(),
    };
    let _ = state.storage.insert_event(&user_id, &telemetry_row).await;

    // Run full SDK evaluation pipeline (deterministic, no I/O)
    let result: EvaluationResult = state.sdk.evaluate(&event, &profile);
    let eval_ms = start.elapsed().as_millis() as i64;

    let decision_str = format!("{:?}", result.decision);

    // Record audit log
    let audit_entry = AuditEntry {
        timestamp: Utc::now(),
        user_id: user_id.clone(),
        trust_score: result.trust_score,
        decision: result.decision.clone(),
        reasons: result.reasons.clone(),
    };
    let audit_id = state
        .storage
        .record_decision(&audit_entry, result.risk_score, result.explanation.clone(), eval_ms)
        .await
        .ok()
        .map(|id| id.to_string());

    // Broadcast WebSocket events
    let _ = state.ws_tx.send(WsEvent::TrustEvaluated {
        user_id: payload.user_id.clone(),
        trust_score: result.trust_score,
        risk_score: result.risk_score,
        decision: decision_str.clone(),
        evaluation_time_ms: eval_ms,
        timestamp: Utc::now(),
    });

    if result.requires_multi_sig {
        let _ = state.ws_tx.send(WsEvent::MultiSigRequired {
            user_id: payload.user_id.clone(),
            risk_score: result.risk_score,
            timestamp: Utc::now(),
        });
    }

    // ── Prometheus metrics ──────────────────────────────────────────────────
    let eval_secs = start.elapsed().as_secs_f64();
    telemetry::TRUST_EVALUATIONS_TOTAL
        .with_label_values(&[&decision_str, "evaluate"])
        .inc();
    telemetry::TRUST_EVALUATION_DURATION_SECONDS
        .with_label_values(&["evaluate"])
        .observe(eval_secs);

    info!(
        user_id = %payload.user_id,
        trust_score = result.trust_score,
        risk_score = result.risk_score,
        decision = %decision_str,
        eval_ms = eval_ms,
        "Trust evaluation complete"
    );

    Ok(ApiResponse::ok_with_latency(
        EvaluateResponse {
            user_id: payload.user_id,
            risk_score: result.risk_score,
            trust_score: result.trust_score,
            decision: decision_str,
            requires_multi_sig: result.requires_multi_sig,
            risk_factors: result.reasons,
            explanation: result.explanation,
            audit_id,
        },
        request_id,
        Some(eval_ms),
    ))
}

fn parse_action_type(s: &str) -> ActionType {
    match s.to_lowercase().as_str() {
        "login" => ActionType::Login,
        "logout" => ActionType::Logout,
        "transaction" => ActionType::Transaction,
        "approval" => ActionType::Approval,
        _ => ActionType::SessionPing,
    }
}
