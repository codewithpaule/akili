# Phone Intelligence Module — Design & Spec

This document describes a lawful, privacy-preserving phone-number intelligence system for fraud prevention, account recovery, and digital risk investigations. The architecture, tech stack, database schema, OSINT workflow, API, threat model, privacy safeguards, UI guidance, and sample responses are included.

## Goals
- Accept a phone number input and return normalized, evidence-backed intelligence.
- Use only publicly available, consented, or licensed datasets configured by environment variables (do not use HIBP unless enabled).
- Provide privacy-safe outputs (no location/GPS, no private carrier systems access).
- Rate limit and audit all investigator access.

## High-level System Architecture
- Frontend (investigator dashboard) — single-page pages under `frontend/`.
- Backend API (FastAPI) — new module `phone_intel` exposing endpoints under `/api/v1/phone`.
- Workers (optional) — background enrichment tasks for slow sources, queue via Redis/RQ or Celery.
- Data stores: PostgreSQL for normalized records, Redis for rate-limits and short caches, object store for artifacts if needed.
- Search & enrichment: licensed datasets (configurable), web search (SerpAPI or alternative), social media public scraping (where allowed), and configured breach provider (use the configured env var like `BREACH_API_URL` or custom `XPOSED` checker in `.env`).
- Auditing: append-only audit log table capturing user_id, api_key, request_id, query, redaction flags, timestamp.

Architecture diagram (logical):
Frontend ⇄ FastAPI API ⇄ Enrichment Workers ⇄ (Postgres, Redis, Licensed Data APIs, Web Search)

## Recommended Tech Stack
- Backend: Python 3.11+, FastAPI, SQLAlchemy (async optional), Pydantic.
- Queue/workers: Redis + RQ or Celery (simple choice: RQ for low ops overhead).
- DB: PostgreSQL (for production), SQLite for local dev.
- Cache/Rate-limit: Redis with `slowapi` or `fastapi-limiter`.
- HTTP clients: `httpx` (async), `aiolimiter` for external provider rate limits.
- Frontend: existing vanilla JS stack; add phone page and dashboard components.
- Auth: existing JWT flows. Reuse the same `JWT_SECRET` for API auth so web UI and API tokens are interoperable.
- Storage: S3-compatible object store (optional) for artifacts.
- Containerization: Docker + deploy via Fly or similar.

## Database Schema (Postgres)
- phone_queries (stores normalized queries)
  - id: uuid PK
  - normalized: text (E.164)
  - raw_input: text
  - country: text
  - carrier: text
  - line_type: enum('mobile','landline','voip','unknown')
  - risk_score: integer (0-100)
  - risk_reason: text
  - username_matches: jsonb (array of {platform, handle, url, confidence})
  - breach_signal: boolean
  - breach_count: integer
  - sources: jsonb (list of sources checked)
  - investigator_id: uuid NULL
  - api_key_id: uuid NULL
  - created_at: timestamp
  - updated_at: timestamp

- phone_query_logs (audit)
  - id: uuid PK
  - phone_query_id: uuid FK
  - actor_user_id: uuid
  - actor_api_key: uuid
  - action: text (search,enrich,export)
  - request_ip: inet
  - reason: text (freeform investigator note)
  - redacted: boolean
  - created_at: timestamp

- phone_sources_cache (fast cache)
  - id: uuid
  - normalized: text
  - payload: jsonb
  - ttl_expires: timestamp

## OSINT Workflow Pipeline
1. Input normalization & validation
   - Parse and normalize to E.164 using libphonenumber (python-phonenumbers). Reject invalid numbers.
   - Extract country code for region inference.
2. Rapid checks (synchronous, fast)
   - Carrier lookup (libphonenumber or licensed carrier DB)
   - Line-type detection (mobile/voip/landline)
   - Local cache lookup (Redis/postgres) for recent queries
3. Enrichment (parallel, with timeouts)
   - Breach exposure check: call configured breach provider (configured in `.env`), return only a boolean/count and source names — do NOT return email addresses or sensitive PII
   - Public web search for exact number strings and username handles (search_with_fallback)
   - Social linking: detect URLs, profiles, or usernames matching the number (where publicly linked)
   - Scam-report aggregation: query public consumer complaint datasets or licensed spam lists
   - Reputation scoring: combine signals (frequency in public complaints, spam reports, scam keywords, association with flagged handles)
4. Correlation & scoring
   - Correlate usernames/aliases across platforms and compute confidence per match
   - Compute risk score (0–100) using weighted features
5. Return sanitized result; persist query and audit log

## Rate limiting & Abuse Prevention
- Enforce per-account and per-api-key daily caps (existing `UsageCounter` + daily period key). Example: 20 scans/day for trial accounts.
- Per-IP rate limit for unauthenticated requests.
- Require JWT or API key for investigator-level access. API key creation remains free (no payment) and uses same JWT for auth compatibility.
- Long-running enrichments are queued; results accessible via poll/push callback.

## API Endpoints (examples)
- POST /api/v1/phone/normalize
  - body: { "phone": "+2348012345678" }
  - returns: { "e164": "+2348012345678", "valid": true, "country": "NG", "line_type": "mobile" }

- POST /api/v1/phone/scan
  - body: { "phone": "+2348012345678", "reason": "fraud-check" }
  - auth: JWT or X-API-Key
  - returns: { "request_id": "uuid", "status": "complete", "result": { ... } }

- GET /api/v1/phone/scan/{request_id}
  - returns the enriched result and audit metadata

- GET /api/v1/phone/lookup?phone=... (fast cached lookup)

Notes: All endpoints must log actor and purpose to `phone_query_logs` and enforce rate-limits.

## Risk-Scoring Methodology
- Features and weights (example):
  - Breach exposure signal: 30
  - Presence in scam/complaint lists: 25
  - Multiple public complaint matches: 20
  - Known spam reporter count: 10
  - VOIP/temporary number: 10
  - Low-confidence/one-off mentions: -10 (lowers score)
- Score = clamp(sum(weights * signals), 0, 100)
- Provide per-feature contributions in response for explainability.

## Privacy & Legal Safeguards
- Only use public, consented, or licensed data sources configured from environment variables.
- Do not return raw breach entries or email addresses. Only expose `breach_signal` (boolean) and `breach_count` (integer), and named sources.
- No geolocation beyond country/approximate region when publicly available and legally permissible.
- Retention policy: default 30 days for query results; retention configurable per deployment and data source contract.
- Investigator access controls: RBAC (roles: investigator, admin), purpose logging, and just-in-time consent checks where required.
- Export redaction: exports should mask PII unless explicitly authorized and logged.
- Data minimization and right-to-be-forgotten support: deletion endpoints removing stored query data and logs if legally required.

## Threat Model
- Adversaries: malicious users trying to mass-enumerate phone numbers, scrape private data, or use the API for harassment.
- Protections:
  - Enforce daily per-account and per-key caps
  - Require JWT/API key and usage logging
  - Rate-limit and anomaly detection
  - Blocklisted IPs and throttling for excessive patterns
  - Do not accept free-form queries that request private lookups (e.g., "track device") — only support permitted use-cases.

## False-Positive Mitigation
- Provide confidence per signal and overall confidence.
- Show raw evidence links (URLs) so investigators can verify matches.
- Use conservative heuristics for username/alias correlation; require multiple signals for high confidence.

## UI Wireframe (investigator dashboard)
- Input panel: phone input + reason + optional note
- Summary card: normalized phone, country, carrier, line-type, risk score (0–100) with colored badge
- Evidence tabs: Breaches (signal/count), Social matches (list of handles + confidence), Complaint reports (links + excerpts), Images (public profile pics)
- Timeline / History: previous queries with quick-open
- Actions: mark as false positive, export redacted report, request deeper licensed data (if available)

## Example JSON Response (successful)
{
  "request_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "phone": "+2348012345678",
  "normalized": "+2348012345678",
  "country": "NG",
  "carrier": "MTN Nigeria",
  "line_type": "mobile",
  "risk_score": 72,
  "risk_breakdown": {
    "breach_signal": 1,
    "breach_count": 2,
    "scam_reports": 1,
    "voip": 0,
    "username_correlations": 2
  },
  "username_matches": [
    { "platform": "twitter", "handle": "akili_ops", "url": "https://twitter.com/akili_ops", "confidence": 78 },
    { "platform": "facebook", "handle": "Akili Solutions", "url": "https://facebook.com/akili.solutions", "confidence": 45 }
  ],
  "breach_signal": true,
  "breach_count": 2,
  "sources": ["xposedornot", "scamdb"],
  "confidence": 78,
  "created_at": "2026-05-25T12:34:56Z"
}

## Integration notes for this codebase
- Reuse existing `UsageCounter` logic (already switched to daily keys) to enforce phone scan daily caps.
- Use existing `agent` pattern for streaming longer enrichments; however phone scans should return a synchronous quick result and enqueue deep enrichments to workers.
- Configure breach provider via `.env` (e.g. `BREACH_API_URL` or keep `XPOSED` logic) and avoid HIBP unless the env points to it.
- Ensure all returned fields are privacy-safe and do not include raw breach PII.

---

If you want, I can now scaffold the backend `phone_intel` module (FastAPI routes, DB models, and a simple frontend page) and wire rate-limits and auditing. Do you want me to implement that now?