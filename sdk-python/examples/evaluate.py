import os
from sentinelmark import SentinelMark, SentinelMarkError

def main():
    # Initialize the client with an API key from your environment
    api_key = os.getenv("SENTINELMARK_API_KEY", "sm_live_12345")
    
    # Enable debug mode to see raw requests/responses
    client = SentinelMark(api_key=api_key, debug=True)

    try:
        # Evaluate a transfer event through the Trust Engine
        response = client.events.evaluate(
            product_slug="stellarflow",
            event_type="transfer",
            payload={
                "contract_address": "0x123abc...",
                "transfer_amount_wei": "5000000000000000000",
                "wallet_address": "0x987def..."
            },
            idempotency_key="req_txn_89712398123" # Safe retries
        )

        print("Trust Engine Decision:", response["data"]["decision"])
        print("Risk Score:", response["data"]["risk_score"])
        print("Latency:", response["latency_ms"], "ms")

    except SentinelMarkError as e:
        print(f"Failed to evaluate event: {e}")

if __name__ == "__main__":
    main()
