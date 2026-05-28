Post-deploy ops: DB migrations, env vars, restart

1) Run DB migration (adds `scan_logs` and OTP columns)

On the server (activate your venv if used):

```bash
cd /path/to/akili/backend
python -c "from database import init_db; init_db()"
```

This runs `create_all()` + `migrate_schema()` which will create `scan_logs` and add new `users` columns.

2) Restart the API service

If running under systemd (example service `akili-api`):

```bash
sudo systemctl restart akili-api
sudo journalctl -u akili-api -f
```

Or if running with `uvicorn` directly (example):

```bash
# from repository root
cd backend
# with virtualenv activated
uvicorn main:app --host 0.0.0.0 --port 8001 --reload
```

3) Recommended environment variables

- `AGENT_ALLOWED_HOSTS` — comma-separated hostnames the agent may open when following LLM actions. Example (restrictive):

```env
AGENT_ALLOWED_HOSTS=example.com,assets.example.com
```

- `MAX_AGENT_ACTIONS` — per-scan LLM-driven action limit (open pages / run_tool). Default in code: `6`. Consider lowering to `3` for stricter control:

```env
MAX_AGENT_ACTIONS=3
```

Apply these in your environment (systemd service file, Docker, or platform env config) and restart the API.

4) Quick verification

- Trigger a normal authenticated scan from the frontend and observe streaming logs in the UI.
- Select a running session and confirm logs keep updating (frontend polls `/api/v1/scan/{scan_id}/logs`).
- Check DB for `scan_logs` rows:

```bash
# PostgreSQL example
psql $DATABASE_URL -c "select scan_id, kind, message, timestamp from scan_logs order by timestamp desc limit 10;"
```

5) Notes on monitoring & rate limits

- The code now increments per-user usage counters when an authenticated scan starts (`increment_usage`). Use the `usage_counters` table for alerting.
- For production, wire `usage_counters` to your metrics/alerting (Prometheus export or periodic aggregator) and set alerts on sudden spikes or high per-user counts.

If you want, I can:
- Run a small smoke test script locally to exercise scan + logs
- Add a migration script/management CLI command to run from CI
- Wire basic Prometheus metrics endpoints for `usage_counters` and `scan_logs` counts
