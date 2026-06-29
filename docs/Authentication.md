# Authentication

The SentinelMark API uses API keys to authenticate requests. You can view and manage your API keys in the SentinelMark Dashboard.

Your API keys carry many privileges, so be sure to keep them secure! Do not share your secret API keys in publicly accessible areas such as GitHub, client-side code, and so forth.

Authentication to the API is performed via HTTP Bearer Auth. Provide your API key as the bearer token value.

```http
Authorization: Bearer sm_live_xxx
```

All API requests must be made over HTTPS. Calls made over plain HTTP will fail. API requests without authentication will also fail.

## Key Types
- `sm_test_...` - Test mode keys. Events evaluated in test mode do not pollute your production behavioral profiles.
- `sm_live_...` - Production mode keys.

When using an official SDK, the key is automatically injected:
```typescript
const client = new SentinelMark({ apiKey: "sm_live_xxx" });
```
