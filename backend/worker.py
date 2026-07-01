import os
import time
import logging

from dotenv import load_dotenv
load_dotenv()

from agent import run_agent
from database import append_scan_log

logger = logging.getLogger('akili.worker')


def run_agent_job(module: str, target: str, scan_id: str, user_id: str = '', scan_tier: str = 'trial'):
    """Background job wrapper that runs the agent and persists logs to DB."""
    # Concurrency and timeout controls
    REDIS_URL = os.getenv('REDIS_URL') or os.getenv('REDIS_URI')
    max_concurrent = int(os.getenv('AGENT_MAX_CONCURRENT_JOBS_PER_USER', '2') or 2)
    job_timeout = int(os.getenv('AGENT_JOB_TIMEOUT_SECONDS', '3600') or 3600)
    redis_client = None
    lock_key = None
    acquired = False
    start_time = time.time()
    try:
        if REDIS_URL and user_id:
            try:
                import redis as _redis
                conn = _redis.from_url(REDIS_URL)
                redis_client = conn
                lock_key = f"running_jobs:{user_id}"
                cur = conn.incr(lock_key)
                if cur == 1:
                    # set expiry to avoid stale counters
                    conn.expire(lock_key, job_timeout + 60)
                if cur > max_concurrent:
                    append_scan_log(scan_id, 'CRITICAL', f'User concurrent job limit exceeded ({cur} > {max_concurrent})')
                    save_scan(scan_id, module, target, {"error": "concurrent_limit_exceeded"}, user_id=user_id)
                    # decrement counter and exit
                    try:
                        conn.decr(lock_key)
                    except Exception:
                        pass
                    return
                acquired = True
            except Exception:
                redis_client = None
        # run_agent persists its own progress logs and final report. This wrapper
        # keeps execution detached from the browser connection.
        for chunk in run_agent(module, target, scan_id, lite=False, user_id=user_id, scan_tier=scan_tier):
            # enforce job timeout by checking elapsed time
            if job_timeout and (time.time() - start_time) > job_timeout:
                append_scan_log(scan_id, 'CRITICAL', 'Agent job terminated due to timeout')
                break
        # completed
    except Exception:
        logger.exception('run_agent_job failed')
        append_scan_log(scan_id, 'CRITICAL', 'The background agent stopped unexpectedly. Please retry the scan.')
    finally:
        # release concurrency counter
        try:
            if acquired and redis_client and lock_key:
                try:
                    redis_client.decr(lock_key)
                except Exception:
                    pass
        except Exception:
            pass
