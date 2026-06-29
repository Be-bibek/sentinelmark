# Rate Limits

To guarantee stability and prevent abuse, SentinelMark enforces rate limits on all API requests. Rate limits are applied per Project and per Organization.

## Global Limits
By default, standard API keys are limited to **100 requests per second** across the entire project.

If you exceed this rate limit, the API will respond with an HTTP `429 Too Many Requests` status code and an `SM7001` error code.

## Handling Limits
All official SentinelMark SDKs (Python, Node, Rust, Go) natively include exponential backoff and jitter for `429` responses. If you use the official SDKs, rate limits are handled gracefully under the hood up to the configured `max_retries` (default 3).

If you are calling the API manually, you should inspect the headers and retry accordingly.

## Enterprise Limits
If your application requires sustained throughput beyond 100 requests per second, please contact enterprise support to provision dedicated ingestion clusters.
