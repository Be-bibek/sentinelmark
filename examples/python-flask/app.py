from flask import Flask, request, jsonify
from sentinelmark import SentinelMark, SentinelMarkError
import os
import uuid

app = Flask(__name__)

# Initialize SentinelMark with your API Key
api_key = os.getenv("SENTINELMARK_API_KEY", "sm_test_1234")
sm_client = SentinelMark(api_key=api_key)

@app.route('/transfer', methods=['POST'])
def handle_transfer():
    data = request.json
    
    # 1. Gather context
    amount = data.get("amount")
    wallet = data.get("wallet")
    
    # 2. Ask SentinelMark for a Trust Decision
    try:
        decision_resp = sm_client.events.evaluate(
            product_slug="stellarflow",
            event_type="transfer",
            payload={
                "transfer_amount_wei": str(amount),
                "wallet_address": wallet,
                "contract_address": "0xABC123"
            },
            idempotency_key=str(uuid.uuid4()) # Safe retries
        )
        
        action = decision_resp["data"]["decision"]
        risk = decision_resp["data"]["risk_score"]
        
        # 3. Enforce the Policy
        if action == "BLOCK":
            return jsonify({"error": "Transaction blocked due to high risk.", "risk": risk}), 403
        elif action == "MFA":
            return jsonify({"status": "Requires Step-Up Auth", "risk": risk}), 401
            
        # 4. Proceed normally
        return jsonify({"status": "Transfer Successful", "risk": risk}), 200

    except SentinelMarkError as e:
        # Fallback open if Trust Engine is unreachable
        print(f"Trust Engine Error: {e}")
        return jsonify({"status": "Transfer Successful (Unverified)"}), 200

if __name__ == '__main__':
    app.run(port=5000)
