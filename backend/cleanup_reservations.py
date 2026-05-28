"""Cleanup expired scan reservations.

Run this periodically (cron / scheduler / RQ Scheduler) to remove stale reservations
that were reserved but not consumed (to return quota after TTL). When deleting
an expired reservation we decrement the `scan_usage` counter for the date the
reservation was created so the user's consumed daily scans are returned.
"""
import time
from datetime import datetime
from database import get_db, Reservation, ScanUsage


def cleanup_expired(now: int = None) -> int:
    now = int(time.time()) if now is None else int(now)
    deleted = 0
    with get_db() as db:
        rows = db.query(Reservation).filter(Reservation.expires_at > 0, Reservation.expires_at < now).all()
        deleted = len(rows)
        for r in rows:
            try:
                # Determine the UTC date when the reservation was created
                try:
                    created_date = datetime.utcfromtimestamp(r.created_at).strftime("%Y-%m-%d")
                except Exception:
                    created_date = datetime.utcnow().strftime("%Y-%m-%d")

                # Decrement the scan_usage counter for that user/date if present
                usage_row = db.query(ScanUsage).filter(ScanUsage.user_id == r.user_id, ScanUsage.date == created_date).first()
                if usage_row and (usage_row.scan_count or 0) > 0:
                    usage_row.scan_count = max(0, (usage_row.scan_count or 0) - 1)

                # Delete the reservation
                db.delete(r)
            except Exception:
                db.rollback()
    return deleted


if __name__ == '__main__':
    n = cleanup_expired()
    print(f"Removed {n} expired reservations")
