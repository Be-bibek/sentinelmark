# Errors

SentinelMark uses conventional HTTP response codes to indicate the success or failure of an API request. In general: Codes in the `2xx` range indicate success. Codes in the `4xx` range indicate an error that failed given the information provided (e.g., a required parameter was omitted). Codes in the `5xx` range indicate an error with SentinelMark's servers.

Every error response guarantees a standard JSON shape featuring a specific `error_code` mapped to an internal registry:

```json
{
  "success": false,
  "error_code": "SM1001",
  "message": "Invalid API Key",
  "request_id": "84820934-8c76-47b2-b7e1-8818c39e0839",
  "timestamp": "2026-06-30T00:50:00Z"
}
```

## Error Codes
| Code Range | Category | Description |
|---|---|---|
| `SM1xxx` | **Authentication** | Missing, invalid, or revoked API Keys. |
| `SM2xxx` | **Validation** | Malformed payloads, missing required fields. |
| `SM3xxx` | **Trust Engine** | Internal model evaluation failures. |
| `SM4xxx` | **SDK** | Unsupported SDK or protocol versions. |
| `SM5xxx` | **Storage** | Database or persistent layer faults. |
| `SM6xxx` | **Products** | Unmapped products, disabled products in project registry. |
| `SM7xxx` | **Rate Limits** | Exceeded API burst quotas (429). |
| `SM8xxx` | **Internal** | SentinelMark unexpected panics (500). |
