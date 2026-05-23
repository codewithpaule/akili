"""Scheduled tasks — call with CRON_SECRET header from system cron."""

import os
import time

from dotenv import load_dotenv

load_dotenv()

CRON_SECRET = (os.getenv("CRON_SECRET", "") or "").strip()


def verify_cron_secret(provided: str) -> bool:
    if not CRON_SECRET:
        return False
    import hmac
    return hmac.compare_digest(CRON_SECRET, (provided or "").strip())


def run_renewal_reminder_batch() -> dict:
    """Email premium users whose renewal is within 7 days."""
    from database import User, get_db
    from auth_service import maybe_send_renewal_reminder

    sent = 0
    checked = 0
    now = int(time.time())
    with get_db() as db:
        rows = db.query(User).filter(
            User.is_active == True,
            User.plan == "premium",
            User.premium_until > now,
        ).all()
        checked = len(rows)
        user_ids = [r.user_id for r in rows]
    for uid in user_ids:
        try:
            with get_db() as db:
                row = db.query(User).filter(User.user_id == uid).first()
                if not row:
                    continue
                before = int(getattr(row, "renewal_reminder_at", None) or 0)
                maybe_send_renewal_reminder(row)
                after = int(getattr(row, "renewal_reminder_at", None) or 0)
                if after > before:
                    sent += 1
        except Exception:
            pass
    return {"renewal_reminders_sent": sent, "checked": checked}
