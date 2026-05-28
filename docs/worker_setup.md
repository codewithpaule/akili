**Worker Setup**

- **Purpose**: Run background scan jobs using RQ (Redis Queue) to scale scans without blocking web workers.
- **Install**: `pip install rq redis`
- **Env**: Set `REDIS_URL` (e.g., `redis://:password@redis-host:6379/0`).
- **Start worker**:
  - `rq worker scans --url $REDIS_URL --path backend`
  - Or with Python module: `python -m rq worker scans`
- **Notes**:
  - The API will return `{ "status": "queued", "scan_id": "..." }` when a job is enqueued.
  - Worker will run `backend/worker.py::run_agent_job` which writes `scan_logs` as the job progresses.
  - Ensure `DATABASE_URL` is reachable from worker host.
   - **Where to get `REDIS_URL`**: You can provision Redis via your cloud provider (e.g., AWS Elasticache, Azure Cache, GCP Memorystore), use a managed Redis provider like Upstash, or create a Fly Redis instance with `fly redis create` which will output a Redis connection string. Use that connection string as `REDIS_URL`.
   - **Scheduling cleanup**: To periodically remove expired reservations, run `backend/cleanup_reservations.py` on a scheduler. On Fly you can create a cron with `fly cron create --schedule "@hourly" --command "python backend/cleanup_reservations.py"` or run the script via an external cron job.

  - **Using `rq-scheduler` (recommended)**:
    - Register the scheduled job once (stores schedule in Redis):

  ```bash
  # from repository root
  cd backend
  python register_scheduler.py
  ```

    - Run the scheduler daemon that enqueues scheduled jobs at runtime:

  ```bash
  # start the rqscheduler process that will enqueue jobs as scheduled
  rqscheduler --url "$REDIS_URL"
  # or (if entrypoint not available) run the module
  python -m rq_scheduler --url "$REDIS_URL"
  ```

    - Ensure `rqscheduler` is running (supervised) alongside your RQ workers; the scheduler enqueues the cleanup job and workers execute it.
