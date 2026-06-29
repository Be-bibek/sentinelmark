pub mod models;

use models::{ActionPolicy, DicomTracePayload, EventIngestRequest, ProofTrace5GPayload, StellarFlowPayload};
use std::collections::HashMap;
use std::sync::Arc;

/// The core Plugin Trait that all product adapters must implement
pub trait ProductAdapter: Send + Sync {
    /// Validates the structure and integrity of the raw payload
    fn validate(&self, payload: &serde_json::Value) -> Result<(), String>;
    
    /// Normalizes and returns domain-specific risk signals
    fn analyze(&self, payload: &serde_json::Value) -> Result<AnalysisResult, String>;
}

/// Normalized output from any domain-specific analyzer
#[derive(Debug)]
pub struct AnalysisResult {
    pub risk_score: f64,
    pub trust_score: f64,
    pub message: String,
}

/// The Context Engine evaluates the analysis and determines the final Action Policy
pub struct ContextEngine;

impl ContextEngine {
    pub fn evaluate(category: &str, analysis: AnalysisResult) -> ActionPolicy {
        // Context-aware rules based on product category
        let action = match category {
            "fintech" => {
                // Financial products prioritize MFA on moderate risk
                if analysis.risk_score > 0.80 { "BLOCK" }
                else if analysis.risk_score > 0.50 { "MFA" }
                else { "ALLOW" }
            },
            "medical" => {
                // Medical products are extremely strict on any anomaly (Zero Trust)
                if analysis.risk_score > 0.10 { "BLOCK" } else { "ALLOW" }
            },
            "telecom" => {
                // Telecom allows slight jitter but blocks explicit drops
                if analysis.risk_score > 0.90 { "BLOCK" } else { "ALLOW" }
            },
            _ => {
                if analysis.risk_score > 0.85 { "BLOCK" } else { "ALLOW" }
            }
        };

        ActionPolicy {
            action: action.to_string(),
            risk_score: analysis.risk_score,
            trust_score: analysis.trust_score,
            message: analysis.message,
        }
    }
}

// ─── Domain Implementations ───────────────────────────────────────────────────

pub struct DicomAdapter;
impl ProductAdapter for DicomAdapter {
    fn validate(&self, payload: &serde_json::Value) -> Result<(), String> {
        serde_json::from_value::<DicomTracePayload>(payload.clone())
            .map(|_| ())
            .map_err(|e| format!("Invalid DICOM-Trace payload schema: {}", e))
    }

    fn analyze(&self, payload: &serde_json::Value) -> Result<AnalysisResult, String> {
        let data: DicomTracePayload = serde_json::from_value(payload.clone()).unwrap();
        let risk_score = if data.entropy_collapse || data.z_score > 3.0 { 0.95 } else { 0.05 };
        let trust_score = 100.0 - (risk_score * 100.0);
        
        Ok(AnalysisResult {
            risk_score,
            trust_score,
            message: format!("Medical compliance evaluated for instance: {}", data.affected_instance_uid),
        })
    }
}

pub struct ProofTraceAdapter;
impl ProductAdapter for ProofTraceAdapter {
    fn validate(&self, payload: &serde_json::Value) -> Result<(), String> {
        serde_json::from_value::<ProofTrace5GPayload>(payload.clone())
            .map(|_| ())
            .map_err(|e| format!("Invalid ProofTrace-5G payload schema: {}", e))
    }

    fn analyze(&self, payload: &serde_json::Value) -> Result<AnalysisResult, String> {
        let data: ProofTrace5GPayload = serde_json::from_value(payload.clone()).unwrap();
        let risk_score = if data.bit_flip_detected || data.sequence_gap > 5 { 0.99 } else { 0.01 };
        let trust_score = 100.0 - (risk_score * 100.0);

        Ok(AnalysisResult {
            risk_score,
            trust_score,
            message: format!("Network telemetry verified at slice node: {}", data.gnode_b_id),
        })
    }
}

pub struct StellarAdapter;
impl ProductAdapter for StellarAdapter {
    fn validate(&self, payload: &serde_json::Value) -> Result<(), String> {
        serde_json::from_value::<StellarFlowPayload>(payload.clone())
            .map(|_| ())
            .map_err(|e| format!("Invalid StellarFlow payload schema: {}", e))
    }

    fn analyze(&self, payload: &serde_json::Value) -> Result<AnalysisResult, String> {
        let data: StellarFlowPayload = serde_json::from_value(payload.clone()).unwrap();
        let risk_score = if !data.multisig_threshold_met { 0.85 } else { 0.10 };
        let trust_score = 100.0 - (risk_score * 100.0);

        Ok(AnalysisResult {
            risk_score,
            trust_score,
            message: "Financial transaction verified against multisig status.".to_string(),
        })
    }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

pub struct AdapterRegistry {
    adapters: HashMap<String, Arc<dyn ProductAdapter>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        let mut adapters: HashMap<String, Arc<dyn ProductAdapter>> = HashMap::new();
        adapters.insert("dicom-trace".to_string(), Arc::new(DicomAdapter));
        adapters.insert("prooftrace-5g".to_string(), Arc::new(ProofTraceAdapter));
        adapters.insert("stellarflow".to_string(), Arc::new(StellarAdapter));
        
        Self { adapters }
    }

    pub fn get_adapter(&self, slug: &str) -> Option<Arc<dyn ProductAdapter>> {
        self.adapters.get(slug).cloned()
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}
