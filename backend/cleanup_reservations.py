"""Cleanup expired scan reservations.

Run this periodically (cron / scheduler / RQ Scheduler) to remove stale reservations
that were reserved but not consumed (to return quota after TTL).
"""
import time
from database import get_db, Reservation


def cleanup_expired(now: int = None) -> int:
    now = int(time.time()) if now is None else int(now)
    deleted = 0
    with get_db() as db:
        rows = db.query(Reservation).filter(Reservation.expires_at > 0, Reservation.expires_at < now).all()
        deleted = len(rows)
        for r in rows:
            try:
                db.delete(r)
            except Exception:
                db.rollback()
    return deleted


if __name__ == '__main__':
    n = cleanup_expired()
    print(f"Removed {n} expired reservations")
