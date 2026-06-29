import { SentinelMark, SentinelMarkError } from '../src';

async function main() {
  const client = new SentinelMark({
    apiKey: process.env.SENTINELMARK_API_KEY || 'sm_live_12345',
    debug: true,
  });

  try {
    const response = await client.events.evaluate({
      productSlug: 'stellarflow',
      eventType: 'transfer',
      payload: {
        contract_address: '0x123abc...',
        transfer_amount_wei: '5000000000000000000',
        wallet_address: '0x987def...',
      },
      idempotencyKey: 'req_txn_89712398123',
    });

    console.log('Trust Engine Decision:', response.data.decision);
    console.log('Risk Score:', response.data.risk_score);
    console.log('Latency:', response.latency_ms, 'ms');
  } catch (error) {
    if (error instanceof SentinelMarkError) {
      console.error(`Failed to evaluate event: ${error.message} (${error.errorCode})`);
    } else {
      console.error(error);
    }
  }
}

main();
