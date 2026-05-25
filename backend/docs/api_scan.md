# API Scanner — /api/v1/scan/api

Overview
- Runs a safe, configurable API scan against a target URL. Exercises multiple HTTP methods and returns per-method responses and optional diffs.

Authentication & authorization
- Requires an authenticated user session (Bearer token) or a valid API key.
- Access is enforced per-user and per-module via `enforce_scan_access()`.

Rate limits & quotas
- Route-level rate limit: `20` requests per hour (decorator `@limiter.limit("20/hour")`).
- Per-user monthly caps also apply (see `usage_payload()` and plan limits). If the user's monthly cap is reached, the endpoint returns HTTP 429 with a message asking to upgrade.

Request
- Method: POST
- URL: `/api/v1/scan/api`
- Content-Type: `application/json`
- Body schema (JSON):

{
  "url": "https://example.com",            // required
  "methods": ["GET","POST"],            // optional, defaults to GET,HEAD,OPTIONS,POST,PUT,PATCH,DELETE
  "headers": {"X-Test":"value"},        // optional extra headers to inject
  "form_payload": {"q":"search"},      // optional form-encoded payload for POST/PUT/PATCH (Content-Type application/x-www-form-urlencoded)
  "auth": {"type":"basic","username":"u","password":"p"}, // optional auth helper (basic)
  "timeout": 8,                             // optional request timeout in seconds
  "diff": true                              // optional: compute diffs vs GET response
}

Response
- 200 OK: JSON with keys `target`, `results` (array per method) and optional `diffs`.
- Each `results` item contains: `method`, `status_code`, `headers`, `body_preview` (truncated), `body_hash`, and `ok`.
- `diffs` contains unified diffs (text lines) for methods whose responses differ from GET when `diff=true`.

Common error responses
- 401 Unauthorized — "Sign in required or provide a valid API key": no session token or API key provided.
- 403 Forbidden — Module not available on your plan or invalid API key: returned when `enforce_scan_access()` denies the module for the user/plan.
- 429 Too Many Requests — Rate limit exceeded (route-level or monthly module cap reached).
- 415 Unsupported Media Type — If JSON is required and a non-JSON content-type was supplied
- 413 Payload Too Large — Global body size limit enforced by middleware for POST/PUT/PATCH (`MAX_BODY_BYTES`) if the client sends too large a body.
- 500 Internal Server Error — Scanner internal failures (network timeouts, DNS failures, or unexpected exceptions). Message contains a short diagnostic.

Examples
- Basic scan (GET + POST form payload, with admin bearer token):

curl -s -X POST http://localhost:8001/api/v1/scan/api \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"url":"https://example.com","methods":["GET","POST"],"form_payload":{"q":"akili"},"diff":true}'

Notes & safety
- POST/PUT/PATCH requests use a small non-destructive payload by default. Use caution when scanning production APIs — do not send destructive payloads.
- The endpoint does not bypass remote servers' authorization or rate limits; scanning large or aggressive targets may trigger remote protections.
- API keys and tokens are checked and usage incremented by `lookup_api_key()` and `enforce_scan_access()`; ensure your plan allows the module.

If you want stricter structured error bodies (machine-readable codes) or richer auth flows (Bearer token injection, OAuth flows, header fuzzing, concurrency control), tell me which format you prefer and I will extend the endpoint and docs accordingly.
