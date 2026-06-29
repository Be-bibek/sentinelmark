use sdk_rust::{SentinelMark, EvaluateOptions};
use serde_json::json;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = env::var("SENTINELMARK_API_KEY").unwrap_or_else(|_| "sm_live_12345".to_string());

    let client = SentinelMark::builder(&api_key)
        .debug(true)
        .build()?;

    let options = EvaluateOptions {
        product_slug: "stellarflow".to_string(),
        event_type: "transfer".to_string(),
        payload: json!({
            "contract_address": "0x123abc",
            "transfer_amount_wei": "5000000000000000000",
            "wallet_address": "0x987def"
        }),
        metadata: None,
        idempotency_key: Some("req_txn_89712398123".to_string()),
    };

    let response = client.events.evaluate(&client, options).await?;

    println!("Trust Engine Decision: {}", response.data.decision);
    println!("Risk Score: {}", response.data.risk_score);
    println!("Latency: {} ms", response.latency_ms.unwrap_or(0));

    Ok(())
}
