import os
import time
import json
import logging
from typing import Generator

from dotenv import load_dotenv
load_dotenv()

from agent import run_agent
from database import append_scan_log, save_scan

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
        # Run agent generator and persist logs
        for chunk in run_agent(module, target, scan_id, lite=False, user_id=user_id, scan_tier=scan_tier):
            # chunk is a string line like '[TOOL] ...' or 'COMPLETE:...'
            try:
                if isinstance(chunk, str):
                    # stream line -> parse kind and message
                    if chunk.startswith('COMPLETE:'):
                        # final report
                        try:
                            report = json.loads(chunk[len('COMPLETE:'):])
                            save_scan(scan_id, module, target, report, user_id=user_id)
                            append_scan_log(scan_id, 'DONE', 'Report ready')
                        except Exception:
                            append_scan_log(scan_id, 'CRITICAL', 'Failed to parse COMPLETE payload')
                    else:
                        # try to split [KIND] message
                        m = chunk.strip()
                        kind = ''
                        msg = m
                        if m.startswith('['):
                            try:
                                k, rest = m.split(']', 1)
                                kind = k.strip('[').strip()
                                msg = rest.strip() if rest else ''
                            except Exception:
                                pass
                        append_scan_log(scan_id, kind or 'AKILI', msg)
            except Exception:
                logger.exception('Error writing scan log')
            # enforce job timeout by checking elapsed time
            if job_timeout and (time.time() - start_time) > job_timeout:
                append_scan_log(scan_id, 'CRITICAL', 'Agent job terminated due to timeout')
                save_scan(scan_id, module, target, {"error": "timeout"}, user_id=user_id)
                break
        # completed
    except Exception:
        logger.exception('run_agent_job failed')
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
*** End Patch