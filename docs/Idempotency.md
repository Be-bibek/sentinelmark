# Idempotency

The SentinelMark API supports idempotency for safely retrying requests without accidentally performing the same operation twice. This is extremely useful when an API call is disrupted in transit and you do not receive a response.

For example, if a request to `events.evaluate()` fails due to a network connection error, you can retry the request with the same idempotency key to guarantee that the trust engine does not double-count the behavioral telemetry.

## Using Idempotency

To perform an idempotent request, provide an additional `Idempotency-Key: <key>` header to the request.

SentinelMark's idempotency works by saving the resulting status code and body of the first request made for any given idempotency key, regardless of whether it succeeded or failed. Subsequent requests with the same key return the same result.

Keys expire automatically after **24 hours**.

### Via SDK
All official SDKs support passing an idempotency key directly:

```go
client.Events.Evaluate(ctx, sentinelmark.EvaluateOptions{
    ProductSlug: "stellarflow",
    EventType: "transfer",
    Payload: map[string]interface{}{ "amount": 500 },
    IdempotencyKey: "req_txn_89712398123", // Set key here
})
```
