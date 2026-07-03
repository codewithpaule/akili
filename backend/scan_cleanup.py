"""Ephemeral scan cleanup — purge target data after delivery to reduce server-side footprint."""

from __future__ import annotations

import logging
import os
import time

logger = logging.getLogger("akili.cleanup")

SCAN_RETENTION_SECONDS = int(os.getenv("SCAN_RETENTION_SECONDS", "900") or 900)
SCAN_EPHEMERAL = (os.getenv("SCAN_EPHEMERAL", "1") or "1").strip().lower() not in ("0", "false", "no")


def schedule_scan_purge(scan_id: str, delay_seconds: int | None = None) -> None:
    """Schedule purge after delay. Uses Redis if available, else runs inline after delay in thread."""
    if not SCAN_EPHEMERAL or not scan_id:
        return
    delay = delay_seconds if delay_seconds is not None else SCAN_RETENTION_SECONDS

    redis_url = os.getenv("REDIS_URL") or os.getenv("REDIS_URI")
    if redis_url:
        try:
            from datetime import timedelta
            from rq import Queue
            import redis as _redis

            conn = _redis.from_url(redis_url)
            q = Queue("cleanup", connection=conn)
            q.enqueue_in(timedelta(seconds=max(60, delay)), purge_scan_now, scan_id)
            return
        except Exception:
            logger.debug("RQ delayed purge unavailable, using thread fallback")

    import threading

    def _delayed():
        time.sleep(max(60, delay))
        purge_scan_now(scan_id)

    threading.Thread(target=_delayed, daemon=True, name=f"purge-{scan_id[:8]}").start()


def purge_scan_now(scan_id: str) -> bool:
    from database import purge_scan_ephemeral

    try:
        ok = purge_scan_ephemeral(scan_id)
        if ok:
            logger.info("Purged ephemeral scan data for %s", scan_id[:8])
        return ok
    except Exception:
        logger.exception("Failed to purge scan %s", scan_id[:8])
        return False


def cleanup_expired_scans(max_age_seconds: int | None = None) -> int:
    """Batch cleanup for scans older than retention window."""
    from database import purge_scans_older_than

    age = max_age_seconds if max_age_seconds is not None else SCAN_RETENTION_SECONDS
    try:
        return purge_scans_older_than(age)
    except Exception:
        logger.exception("Batch scan cleanup failed")
        return 0
