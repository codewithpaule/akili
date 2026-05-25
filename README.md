# AKILI

**See everything others miss.** — AI-powered cybersecurity and trust intelligence platform.

- **Backend:** FastAPI + Groq (`llama-3.3-70b-versatile`) + SQLite/PostgreSQL  
- **Frontend:** Pure HTML/CSS/JS (Cabinet Grotesk, DM Sans, JetBrains Mono)  
- **Deploy:** Railway (API) + Vercel (static frontend)

## Quick start

### Backend (port 8000 — or use a second terminal if RECON-X is on 8000)

```powershell
cd akili\backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
# Set GROQ_API_KEY, SERPAPI_KEY, optional SHODAN_API_KEY, VIRUSTOTAL_KEY
uvicorn main:app --reload --host 0.0.0.0 --port 8001
```

**How to know it is live**

1. Health: open `http://localhost:8001/api/v1/health` — expect `{"status":"ok","groq":"connected"}`.
2. Frontend navbar dot turns green and shows **LIVE** when the API responds and Groq is connected.
3. Run any scan (e.g. website) — terminal lines stream and results save to History.

Person/company OSINT uses **SerpAPI** first (`SERPAPI_KEY` in `.env`); DuckDuckGo/Google/Bing are optional fallbacks.

### Frontend (port 5501)

```powershell
cd akili\frontend
python -m http.server 5501
```

Open **http://localhost:5501** — set `frontend/js/config.js`:

```javascript
window.AKILI_CONFIG = { API_BASE: 'http://localhost:8001' };
```

Set `ALLOWED_ORIGINS` in `backend/.env` to match:

```env
ALLOWED_ORIGINS=http://localhost:5501,http://127.0.0.1:5501
```

## Platform pages

| Page | Purpose |
|------|---------|
| `index.html` | Landing — hero terminal, modules, D3 graph, GSAP |
| `scan-website.html` | Website security scan |
| `scan-vulnerability.html` | Vuln assessment |
| `scan-subdomains.html` | Subdomain discovery |
| `scan-ip.html` | IP intelligence (public IPs only) |
| `scan-organization.html` | Org / ASN footprint |
| `person.html` | Person OSINT |
| `company.html` | Company intel |
| `email.html` | Email investigator |
| `domain.html` | Domain reputation |
| `graph.html` | Relationship graph (D3) |
| `monitor.html` | Watchlist |
| `history.html` / `report.html` | Scan archive |
| `developer.html` | API keys |
| `docs.html` | API documentation |
| `sandbox.html` | Mock API testing |
| `about.html` / `contact.html` / `privacy.html` | Company & NDPR |

## API (v1)

Base: `{API_BASE}/api/v1`

- `POST /scan/website` — body `{ "url": "https://..." }` → streaming `COMPLETE:{json}`
- `POST /scan/person` — `{ "name", "keywords" }`
- `POST /scan/ip` — `{ "ip": "8.8.8.8" }` (public only)
- `GET /report/{scan_id}` — full report
- `GET /history` — paginated metadata
- `POST /keys/generate` — API key (shown once, SHA-256 stored)
- `POST /sandbox/scan/website?scenario=critical_vulns` — mock data

## Developer docs

- API scanner documentation: [backend/docs/api_scan.md](backend/docs/api_scan.md)

**Auth:** `X-API-Key: ak_live_...` or browser (10 scans/hour/IP).

## Rate limits

| Tier | Limit |
|------|-------|
| Browser (no key) | 10/hour |
| Free (`ak_live_`) | 50/hour |
| Pro | 500/hour |
| Sandbox (`ak_test_`) | Unlimited (mock only) |

## Security

- SSRF protection (private IPs blocked)
- Targets never logged — only `scan_id`, `timestamp`, `scan_type`
- API keys hashed with SHA-256
- Security headers on all responses
- Authorized-use disclaimers on scan pages

## Ethics

Use only on systems and subjects you are authorized to assess. Person search is **public data only** for legitimate due diligence.

## RECON-X vs AKILI

Both live under `cybersec/`:

- `recon-x/` — dark cyberpunk UI (Orbitron), port 5500 / 8000  
- `akili/` — white professional UI (Cabinet Grotesk), port 5501 / 8001 recommended
