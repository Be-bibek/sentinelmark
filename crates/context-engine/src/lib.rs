use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Enriched context for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventContext {
    pub product: String,
    pub event_type: String,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    pub device_fingerprint: Option<String>,
    pub user_agent: Option<String>,
    pub variables: HashMap<String, Value>,
    pub payload: Value,
}

impl EventContext {
    /// Extracts context from raw payload and request metadata.
    pub fn enrich(
        product: &str,
        event_type: &str,
        payload: &Value,
        metadata: &Value,
        variables: HashMap<String, Value>,
    ) -> Self {
        // Extract basic network context from metadata if provided
        let ip_address = metadata.get("ip_address").and_then(|v| v.as_str()).map(|s| s.to_string());
        
        // Mock GeoIP resolution (in a real system, this would call a GeoIP database or service)
        let country = metadata.get("country").and_then(|v| v.as_str()).map(|s| s.to_string())
            .or_else(|| {
                // Dummy logic for demo
                ip_address.as_ref().and_then(|ip| {
                    if ip.starts_with("104.") { Some("IN".to_string()) }
                    else if ip.starts_with("94.") { Some("RU".to_string()) }
                    else { Some("US".to_string()) }
                })
            });

        let device_fingerprint = metadata
            .get("device_fingerprint")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
            
        let user_agent = metadata
            .get("user_agent")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Self {
            product: product.to_string(),
            event_type: event_type.to_string(),
            ip_address,
            country,
            device_fingerprint,
            user_agent,
            variables,
            payload: payload.clone(),
        }
    }
}
