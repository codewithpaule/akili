# AKILI — Production Deployment Plan

This guide covers everything needed to deploy AKILI (FastAPI backend + static frontend + SQLite/PostgreSQL + Paystack) from local dev to production.

---

## 1. Architecture overview

```
                    ┌─────────────────┐
   Users ──────────►│  CDN / Nginx     │  Static: HTML, CSS, JS
                    │  (frontend)     │  FRONTEND_URL → your domain
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  FastAPI API    │  uvicorn / gunicorn
                    │  (backend)      │  Port 8000/8001 behind reverse proxy
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         PostgreSQL      Paystack        Groq / APIs
         (recommended)   webhooks        (keys in .env)
```

| Component | Dev | Production |
|-----------|-----|------------|
| Frontend | Live Server `:5501` | Nginx / Cloudflare Pages / S3+CloudFront |
| API | `uvicorn :8001` | Gunicorn+Uvicorn workers behind Nginx |
| Database | `sqlite:///./akili.db` | `postgresql://...` |
| Auth | JWT in localStorage | HTTPS only, strong `JWT_SECRET` |
| Payments | Paystack test keys | Paystack live keys + webhook URL |
| Admin | `admin-login.html` | Same host, restrict by IP optional |

---

## 2. Pre-deploy checklist

### 2.1 Secrets & environment (backend `.env`)

Copy `backend/.env.example` → `backend/.env` and set **real** values:

| Variable | Required | Notes |
|----------|----------|-------|
| `JWT_SECRET` | **Yes** | 64+ random chars; never commit |
| `DATABASE_URL` | **Yes** | Use PostgreSQL in prod |
| `ALLOWED_ORIGINS` | **Yes** | `https://yourdomain.com` only (no `*`) |
| `FRONTEND_URL` | **Yes** | `https://yourdomain.com` for Paystack callbacks |
| `GROQ_API_KEY` | **Yes** | Scans need LLM |
| `PAYSTACK_*` | If billing | Live keys + `PAYSTACK_PREMIUM_PLAN_CODE` |
| `GOOGLE_CLIENT_ID` | If Google login | Add prod origin in Google Console |
| `ADMIN_EMAIL` | **Yes** | Bootstrap admin account |
| `ADMIN_PASSWORD` | **Yes** | Strong password; rotate after first login |
| `SMTP_*` / `EMAIL_FROM` | **Yes** | Welcome, payment, renewal, password-reset emails |
| `SERPAPI_KEY`, `SHODAN`, etc. | Optional | Improves scan depth |

### 2.2 Frontend config (`frontend/js/config.js`)

```javascript
window.AKILI_CONFIG = {
  API_BASE: 'https://api.yourdomain.com',  // or same-origin /api proxy
  GOOGLE_CLIENT_ID: 'your-google-client-id.apps.googleusercontent.com',
};
```

### 2.3 Security hardening

- [ ] HTTPS everywhere (Let's Encrypt via Certbot or cloud LB)
- [ ] `JWT_SECRET` rotated from dev default
- [ ] CORS `ALLOWED_ORIGINS` lists only your frontend origin(s)
- [ ] Paystack webhook: verify signature (already implemented)
- [ ] Do not expose `admin-login.html` in public nav; optional IP allowlist on `/admin*` paths in Nginx
- [ ] Database backups scheduled (daily minimum)
- [ ] `.env` never in git (confirm `.gitignore`)

### 2.4 Paystack (NGN Premium ₦12,000/month)

1. Paystack Dashboard → **Settings → API Keys** → Live keys into `.env`
2. **Plans** → Create monthly ₦12,000 plan → copy **Plan Code** → `PAYSTACK_PREMIUM_PLAN_CODE`
3. **Settings → Webhooks** → URL: `https://api.yourdomain.com/api/v1/billing/webhook`
4. Test: checkout from dashboard → verify → confirm `subscription_status` in admin panel

### 2.5 Google OAuth

1. Google Cloud Console → OAuth Web client
2. **Authorized JavaScript origins**: `https://yourdomain.com`
3. Same Client ID in `GOOGLE_CLIENT_ID` and `config.js`

---

## 3. Database

### 3.1 SQLite (staging / small)

```env
DATABASE_URL=sqlite:///./akili.db
```

Copy existing `akili.db` to server; run app once — `migrate_schema()` adds columns.

### 3.2 PostgreSQL (recommended production)

```bash
# Example: create DB
createdb akili_prod
```

```env
DATABASE_URL=postgresql://akili_user:STRONG_PASSWORD@localhost:5432/akili_prod
```

`psycopg2-binary` is already in `requirements.txt`. On first deploy:

```bash
cd backend
python -c "from database import init_db; init_db()"
```

### 3.3 Backups

```bash
# PostgreSQL
pg_dump -Fc akili_prod > akili_$(date +%Y%m%d).dump

# SQLite
cp akili.db akili_$(date +%Y%m%d).db
```

Store off-server (S3, Backblaze, etc.).

---

## 4. Backend deployment

### 4.1 Server requirements

- Ubuntu 22.04+ or similar
- Python 3.11+
- 2 GB RAM minimum (scans + Groq are memory/network heavy)
- Outbound HTTPS (Groq, Paystack, tool APIs)

### 4.2 Install

```bash
cd /var/www/akili/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4.3 Systemd service (`/etc/systemd/system/akili-api.service`)

```ini
[Unit]
Description=AKILI API
After=network.target postgresql.service

[Service]
User=www-data
WorkingDirectory=/var/www/akili/backend
EnvironmentFile=/var/www/akili/backend/.env
ExecStart=/var/www/akili/backend/venv/bin/gunicorn main:app \
  -k uvicorn.workers.UvicornWorker \
  -w 2 \
  -b 127.0.0.1:8000 \
  --timeout 300 \
  --access-logfile - \
  --error-logfile -
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable akili-api
sudo systemctl start akili-api
```

> Use `--timeout 300` because scan streams can run several minutes.

### 4.4 Health check

```bash
curl -s https://api.yourdomain.com/api/v1/health | jq
```

Expect `"api": "live"` and `"groq": "connected"` when keys are valid.

---

## 5. Frontend deployment

### 5.1 Option A — Same server (Nginx static)

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    root /var/www/akili/frontend;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Optional: proxy API on same domain
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;          # important for SSE scan streams
        proxy_read_timeout 300s;
    }
}
```

If using same-origin `/api`, set `API_BASE: ''` or `window.location.origin` in `config.js`.

### 5.2 Option B — Cloudflare Pages / Netlify

- Build: none (static files)
- Publish directory: `frontend/`
- Set `API_BASE` to full API URL
- Add custom domain + HTTPS

### 5.3 Admin URLs (not in public nav)

- Login: `https://yourdomain.com/admin-login.html`
- Dashboard: `https://yourdomain.com/admin.html`

---

## 6. Nginx API-only vhost (subdomain)

```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_read_timeout 300s;
        client_max_body_size 1m;
    }
}
```

Update `ALLOWED_ORIGINS=https://yourdomain.com` and `FRONTEND_URL=https://yourdomain.com`.

---

## 7. Admin bootstrap

On API startup, if `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set, AKILI creates or updates that user with `role=admin`.

1. Set in `.env`:
   ```env
   ADMIN_EMAIL=you@yourcompany.com
   ADMIN_PASSWORD=use-a-long-random-password-here
   ```
2. Restart API
3. Open `https://yourdomain.com/admin-login.html`
4. Sign in with those credentials
5. **Remove or change `ADMIN_PASSWORD` in .env** after first login (optional; password in DB is bcrypt-hashed)

From admin panel you can: view all users/scans/keys/contacts, change plans, deactivate users, delete scans, revoke keys.

---

## 8. Monitoring & logs

| What | How |
|------|-----|
| API logs | `journalctl -u akili-api -f` |
| Nginx access | `/var/log/nginx/access.log` |
| Failed payments | Admin → Users → subscription_status |
| Rate limits | slowapi (per-route); tune in `rate_limit.py` |
| Disk | SQLite/Postgres growth + scan JSON blobs |

Suggested alerts: API down, 5xx rate, DB disk > 80%, Paystack webhook failures.

---

## 9. Deploy sequence (step-by-step)

1. **Provision** VPS + domain DNS (A/AAAA → server)
2. **PostgreSQL** create DB + user
3. **Clone** repo to `/var/www/akili`
4. **Backend** venv, `pip install`, `.env` with prod values
5. **`init_db()`** on server
6. **systemd** start API, verify `/api/v1/health`
7. **Nginx** frontend + API proxy, **Certbot** SSL
8. **Paystack** live keys + webhook URL
9. **Google** OAuth prod origins + `config.js`
10. **Smoke test**: register → trial scan → admin login → dashboard billing test (test mode first)
11. **Switch Paystack to live** when ready
12. **Backup** cron + document restore procedure

---

## 10. Rollback plan

1. Keep previous release tag / directory: `/var/www/akili-prev`
2. `systemctl stop akili-api` → swap directories → `systemctl start akili-api`
3. DB: restore last `pg_dump` if schema migration failed
4. Frontend: revert Nginx `root` to previous static build

---

## 11. Post-launch

- [ ] NDPR/privacy: update `privacy.html` with real company details
- [ ] Terms / acceptable use for OSINT scans
- [ ] Support email (`CONTACT_EMAIL`) monitored
- [ ] Monthly: rotate API keys review, dependency updates (`pip audit`)
- [ ] Paystack reconciliation vs admin user list

---

## 12. Quick reference — local vs prod

| | Local | Production |
|---|-------|------------|
| Frontend | `http://localhost:5501` | `https://yourdomain.com` |
| API | `http://localhost:8001` | `https://api.yourdomain.com` |
| DB | SQLite file | PostgreSQL |
| Paystack | Test keys | Live keys |
| Admin | `admin-login.html` | Same path on prod domain |

For questions or runbooks, extend this file with your hosting provider specifics (AWS, DigitalOcean, Render, etc.).

---

## 13. GitHub Auto-Deployment (Git-Push-to-Deploy)

Connecting your GitHub repository to a modern cloud hosting platform allows you to deploy changes automatically on every `git push origin main`. The two easiest and most reliable platforms for this FastAPI + HTML/JS setup are **Render.com** and **Railway.app**.

### Option A: Deploying on Render.com (Recommended)

Render offers first-class support for monorepos, static sites, and managed databases.

#### Step 1: Provision your Database
1. Sign in to [Render.com](https://render.com) and click **New → PostgreSQL**.
2. Name your database, select a region, and choose a plan.
3. Click **Create Database**.
4. Once active, copy the **Internal Database URL** (for backend access) and **External Database URL** (for local migrations/admin check).

#### Step 2: Deploy the FastAPI Backend (Web Service)
1. Click **New → Web Service** and select your GitHub repository.
2. Configure the following settings:
   - **Name**: `akili-api`
   - **Root Directory**: `backend`
   - **Runtime**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn -k uvicorn.workers.UvicornWorker -w 2 -b 0.0.0.0:10000 --timeout 300 main:app`
3. Click **Advanced** and add your Environment Variables:
   - `DATABASE_URL`: *(Paste the Internal Database URL from Step 1)*
   - `JWT_SECRET`: *(A long, random cryptographic string)*
   - `GROQ_API_KEY`: *(Your active Groq AI token)*
   - `FRONTEND_URL`: `https://your-frontend-site.onrender.com` (your frontend URL)
   - `ALLOWED_ORIGINS`: `https://your-frontend-site.onrender.com`
   - `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_PIN` *(For the admin user)*
   - Set other API keys like `SMTP_SERVER`, `SMTP_PASSWORD` for emails, and `PAYSTACK_SECRET_KEY` for billing.
4. Click **Create Web Service**. Render will build and deploy the backend.

#### Step 3: Deploy the Frontend (Static Site)
1. Click **New → Static Site** and select the same GitHub repository.
2. Configure the settings:
   - **Name**: `akili-web`
   - **Root Directory**: `frontend`
   - **Build Command**: *(Leave empty)*
   - **Publish Directory**: `.`
3. Click **Create Static Site**.
4. **Update config**: Once the Static Site is built, copy its URL. Update your local `frontend/js/config.js` to set `API_BASE` to your Render Backend URL, and commit and push this change to GitHub.

---

### Option B: Deploying on Railway.app

Railway is incredibly fast to set up and automatically deploys services in a unified dashboard.

#### Step 1: Create a Railway Project
1. Log in to [Railway.app](https://railway.app) and create a **New Project**.
2. Choose **Provision PostgreSQL** to add a database service.

#### Step 2: Deploy the Backend
1. Click **New → GitHub Repo** and choose your repository.
2. Go to the service **Settings** tab and set the **Root Directory** to `backend`.
3. Railway automatically detects Python and sets up `pip install`. If required, customize the Start Command:
   `gunicorn -k uvicorn.workers.UvicornWorker -w 2 -b 0.0.0.0:$PORT --timeout 300 main:app`
4. Go to the **Variables** tab and bulk import the same environment variables as Render (use `${{Postgres.DATABASE_URL}}` to automatically reference the PostgreSQL database in the same project).

#### Step 3: Deploy the Frontend
1. Click **New → GitHub Repo** again and select your repository.
2. In the service **Settings** tab, set **Root Directory** to `frontend`.
3. In **Variables**, you can set custom domains if needed. Railway will host the static files directly.
4. Set up custom domains for both services, update `frontend/js/config.js` to point to the backend domain, and push the change to GitHub.

Every subsequent `git push` to your main branch will trigger an automated build and zero-downtime deployment for both frontend and backend!
