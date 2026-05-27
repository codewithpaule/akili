"""Admin operations — stats, users, scans, keys, contacts, monitors."""

import os
import re
import time
import uuid
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import HTTPException
from sqlalchemy import func
import json
from html.parser import HTMLParser
from urllib.parse import urlparse
from auth_service import hash_password, user_to_dict
from database import ApiKey, Contact, Monitor, Scan, UsageCounter, User, get_db, period_key

load_dotenv()

ADMIN_EMAIL = (os.getenv("ADMIN_EMAIL", "") or "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "") or ""

ALLOWED_MAIL_TAGS = {
    "a", "b", "blockquote", "br", "div", "em", "h1", "h2", "h3", "i",
    "li", "ol", "p", "span", "strong", "u", "ul",
}
ALLOWED_MAIL_ATTRS = {"a": {"href", "title", "target", "rel"}}


def bootstrap_admin_user() -> None:
    """Create or promote admin from ADMIN_EMAIL / ADMIN_PASSWORD in .env."""
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        return
    now = int(time.time())
    with get_db() as db:
        row = db.query(User).filter(User.email == ADMIN_EMAIL).first()
        if row:
            row.role = "admin"
            row.is_active = True
            if ADMIN_PASSWORD:
                row.password_hash = hash_password(ADMIN_PASSWORD)
            row.updated_at = now
            return
        db.add(User(
            user_id=str(uuid.uuid4()),
            email=ADMIN_EMAIL,
            password_hash=hash_password(ADMIN_PASSWORD),
            name="AKILI Admin",
            plan="premium",
            trial_ends_at=0,
            google_id="",
            created_at=now,
            updated_at=now,
            is_active=True,
            role="admin",
            subscription_status="active",
        ))


def is_admin_user(row: User) -> bool:
    return (getattr(row, "role", None) or "user") == "admin"


def require_admin_row(user_id: str) -> User:
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id, User.is_active == True).first()
        if not row or not is_admin_user(row):
            raise HTTPException(403, "Admin access required")
        return row


def admin_dashboard_stats() -> dict:
    now = int(time.time())
    month_start = now - 30 * 86400
    period = period_key()

    with get_db() as db:
        users_total = db.query(User).filter(User.is_active == True).count()
        users_admin = db.query(User).filter(User.is_active == True, User.role == "admin").count()
        premium = db.query(User).filter(
            User.is_active == True,
            User.plan.in_(["premium", "pro", "business"]),
        ).count()
        trial_active = db.query(User).filter(
            User.is_active == True,
            User.trial_ends_at > now,
        ).count()
        scans_total = db.query(Scan).count()
        scans_month = db.query(Scan).filter(Scan.timestamp >= month_start).count()
        keys_active = db.query(ApiKey).filter(ApiKey.is_active == True).count()
        contacts = db.query(Contact).count()
        monitors = db.query(Monitor).filter(Monitor.is_active == True).count()
        usage_month = (
            db.query(func.coalesce(func.sum(UsageCounter.count), 0))
            .filter(UsageCounter.period == period)
            .scalar()
        ) or 0

        recent_users = (
            db.query(User)
            .filter(User.is_active == True)
            .order_by(User.created_at.desc())
            .limit(8)
            .all()
        )
        recent_users_brief = [_admin_user_brief(u) for u in recent_users]
        recent_scans = db.query(Scan).order_by(Scan.timestamp.desc()).limit(8).all()
        recent_scans_brief = [_scan_brief(s) for s in recent_scans]

    return {
        "users_total": users_total,
        "users_admin": users_admin,
        "premium_users": premium,
        "trial_active": trial_active,
        "scans_total": scans_total,
        "scans_last_30d": scans_month,
        "api_keys_active": keys_active,
        "contacts_total": contacts,
        "monitors_active": monitors,
        "usage_events_this_month": int(usage_month),
        "period": period,
        "recent_users": recent_users_brief,
        "recent_scans": recent_scans_brief,
    }


def _admin_user_brief(row: User) -> dict:
    return {
        "user_id": row.user_id,
        "email": row.email,
        "name": row.name or "",
        "plan": row.plan,
        "role": getattr(row, "role", None) or "user",
        "created_at": row.created_at,
        "subscription_status": getattr(row, "subscription_status", None) or "",
    }


def _scan_brief(row: Scan) -> dict:
    target = row.target if len(row.target) <= 50 else row.target[:47] + "..."
    return {
        "scan_id": row.scan_id,
        "user_id": row.user_id or "",
        "scan_type": row.scan_type,
        "target": target,
        "score": row.score,
        "grade": row.grade,
        "timestamp": row.timestamp,
    }


def list_users_admin(
    *,
    page: int = 1,
    limit: int = 25,
    q: str = "",
    plan: str = "",
    role: str = "",
) -> dict:
    limit = min(max(limit, 1), 100)
    page = max(page, 1)
    with get_db() as db:
        query = db.query(User)
        if q:
            like = f"%{q.strip()}%"
            query = query.filter(
                (User.email.ilike(like)) | (User.name.ilike(like)) | (User.organization.ilike(like))
            )
        if plan:
            query = query.filter(User.plan == plan)
        if role:
            query = query.filter(User.role == role)
        total = query.count()
        rows = (
            query.order_by(User.created_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        items = [_admin_user_detail(r, brief=True) for r in rows]
    return {"items": items, "total": total, "page": page, "limit": limit}


def get_user_admin(user_id: str) -> dict:
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id).first()
        if not row:
            raise HTTPException(404, "User not found")
        scan_count = db.query(Scan).filter(Scan.user_id == user_id).count()
        key_count = db.query(ApiKey).filter(ApiKey.user_id == user_id, ApiKey.is_active == True).count()
        usage = {
            r.module: r.count
            for r in db.query(UsageCounter).filter(UsageCounter.user_id == user_id, UsageCounter.period == period_key()).all()
        }
        out = _admin_user_detail(row, brief=False)
        out["scan_count"] = scan_count
        out["api_key_count"] = key_count
        out["usage_this_month"] = usage
        return out


def _admin_user_detail(row: User, *, brief: bool) -> dict:
    base = user_to_dict(row)
    base["role"] = getattr(row, "role", None) or "user"
    base["is_active"] = row.is_active
    base["google_id"] = row.google_id or ""
    base["paystack_customer_code"] = getattr(row, "paystack_customer_code", None) or ""
    base["paystack_subscription_code"] = getattr(row, "paystack_subscription_code", None) or ""
    base["plan_before_premium"] = getattr(row, "plan_before_premium", None) or ""
    if brief:
        return base
    base["password_set"] = bool(row.password_hash)
    return base


def update_user_admin(user_id: str, fields: dict) -> dict:
    allowed = {
        "name", "plan", "role", "is_active", "trial_ends_at",
        "subscription_status", "premium_until", "phone", "organization",
    }
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id).first()
        if not row:
            raise HTTPException(404, "User not found")
        if fields.get("role") == "admin":
            admins = db.query(User).filter(User.role == "admin", User.is_active == True).count()
            if getattr(row, "role", "user") != "admin" and admins >= 10:
                raise HTTPException(400, "Too many admin accounts")
        for key, val in fields.items():
            if key not in allowed:
                continue
            if key == "is_active":
                row.is_active = bool(val)
            elif key in ("trial_ends_at", "premium_until"):
                setattr(row, key, int(val or 0))
            elif key == "role":
                setattr(row, key, "admin" if val == "admin" else "user")
            elif key == "plan":
                setattr(row, key, str(val or "trial")[:30])
            else:
                setattr(row, key, str(val or "")[:200])
        if fields.get("plan") == "premium" and not getattr(row, "subscription_status", ""):
            row.subscription_status = "active"
        row.updated_at = int(time.time())
    return get_user_admin(user_id)


def admin_set_password(user_id: str, new_password: str) -> None:
    if len(new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id).first()
        if not row:
            raise HTTPException(404, "User not found")
        row.password_hash = hash_password(new_password)
        row.updated_at = int(time.time())


def deactivate_user_admin(user_id: str, *, hard_delete: bool = False) -> dict:
    from auth_service import delete_user_account

    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id).first()
        if not row:
            raise HTTPException(404, "User not found")
        if is_admin_user(row):
            other_admins = (
                db.query(User)
                .filter(User.role == "admin", User.is_active == True, User.user_id != user_id)
                .count()
            )
            if other_admins < 1:
                raise HTTPException(400, "Cannot remove the last admin")
    if hard_delete:
        delete_user_account(user_id, "")
        return {"deleted": True, "user_id": user_id}
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id).first()
        row.is_active = False
        row.updated_at = int(time.time())
    return {"deactivated": True, "user_id": user_id}


def list_scans_admin(
    *,
    page: int = 1,
    limit: int = 30,
    q: str = "",
    scan_type: str = "",
    user_id: str = "",
) -> dict:
    limit = min(max(limit, 1), 100)
    page = max(page, 1)
    with get_db() as db:
        query = db.query(Scan)
        if user_id:
            query = query.filter(Scan.user_id == user_id)
        if scan_type and scan_type != "all":
            query = query.filter(Scan.scan_type == scan_type)
        if q:
            query = query.filter(Scan.target.ilike(f"%{q.strip()}%"))
        total = query.count()
        rows = query.order_by(Scan.timestamp.desc()).offset((page - 1) * limit).limit(limit).all()
        user_emails = {}
        uids = {r.user_id for r in rows if r.user_id}
        if uids:
            for u in db.query(User).filter(User.user_id.in_(uids)).all():
                user_emails[u.user_id] = u.email
        items = []
        for r in rows:
            item = _scan_brief(r)
            item["user_email"] = user_emails.get(r.user_id or "", "")
            items.append(item)
    return {"items": items, "total": total, "page": page, "limit": limit}


def delete_scan_admin(scan_id: str) -> dict:
    with get_db() as db:
        n = db.query(Scan).filter(Scan.scan_id == scan_id).delete()
        if not n:
            raise HTTPException(404, "Scan not found")
    return {"deleted": True, "scan_id": scan_id}


def list_keys_admin(*, page: int = 1, limit: int = 30, user_id: str = "") -> dict:
    limit = min(max(limit, 1), 100)
    page = max(page, 1)
    with get_db() as db:
        query = db.query(ApiKey)
        if user_id:
            query = query.filter(ApiKey.user_id == user_id)
        total = query.count()
        rows = query.order_by(ApiKey.created_at.desc()).offset((page - 1) * limit).limit(limit).all()
        emails = {}
        uids = {k.user_id for k in rows if k.user_id}
        if uids:
            for u in db.query(User).filter(User.user_id.in_(uids)).all():
                emails[u.user_id] = u.email
        items = [{
            "key_id": k.key_id,
            "user_id": k.user_id,
            "user_email": emails.get(k.user_id, ""),
            "key_name": k.key_name,
            "key_preview": k.key_preview,
            "tier": k.tier,
            "is_sandbox": k.is_sandbox,
            "is_active": k.is_active,
            "created_at": k.created_at,
            "last_used": k.last_used,
            "requests_today": k.requests_today,
            "requests_month": k.requests_month,
        } for k in rows]
    return {"items": items, "total": total, "page": page, "limit": limit}


def revoke_key_admin(key_id: str) -> dict:
    with get_db() as db:
        row = db.query(ApiKey).filter(ApiKey.key_id == key_id).first()
        if not row:
            raise HTTPException(404, "Key not found")
        row.is_active = False
    return {"revoked": True, "key_id": key_id}


def list_contacts_admin(*, page: int = 1, limit: int = 30) -> dict:
    limit = min(max(limit, 1), 100)
    page = max(page, 1)
    with get_db() as db:
        total = db.query(Contact).count()
        rows = (
            db.query(Contact)
            .order_by(Contact.timestamp.desc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        items = [{
            "id": c.id,
            "name": c.name,
            "email": c.email,
            "subject": c.subject,
            "message": c.message[:500],
            "timestamp": c.timestamp,
        } for c in rows]
    return {"items": items, "total": total, "page": page, "limit": limit}


def _html_escape(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class _MailSanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag not in ALLOWED_MAIL_TAGS:
            return
        clean_attrs = []
        for key, val in attrs:
            key = key.lower()
            if key not in ALLOWED_MAIL_ATTRS.get(tag, set()):
                continue
            val = str(val or "").strip()
            if key == "href":
                parsed = urlparse(val)
                if parsed.scheme and parsed.scheme.lower() not in {"http", "https", "mailto"}:
                    continue
            if key == "target":
                val = "_blank"
            clean_attrs.append(f'{key}="{_html_escape(val)}"')
        if tag == "a":
            if not any(a.startswith("rel=") for a in clean_attrs):
                clean_attrs.append('rel="noopener noreferrer"')
            if not any(a.startswith("target=") for a in clean_attrs):
                clean_attrs.append('target="_blank"')
        attr_text = (" " + " ".join(clean_attrs)) if clean_attrs else ""
        self.parts.append(f"<{tag}{attr_text}>")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ALLOWED_MAIL_TAGS and tag != "br":
            self.parts.append(f"</{tag}>")

    def handle_data(self, data):
        self.parts.append(_html_escape(data))

    def handle_entityref(self, name):
        self.parts.append(f"&{name};")

    def handle_charref(self, name):
        self.parts.append(f"&#{name};")


def _sanitize_mail_html(html: str) -> str:
    parser = _MailSanitizer()
    parser.feed(html or "")
    body = "".join(parser.parts).strip()
    return f"""
    <div style="font-family:Arial,sans-serif;line-height:1.6;color:#0f172a;max-width:680px;margin:0 auto">
      {body}
      <hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0">
      <p style="font-size:12px;color:#64748b">Sent by AKILI.</p>
    </div>
    """


def _html_to_text(html: str) -> str:
    text = re.sub(r"<\s*br\s*/?>", "\n", html, flags=re.I)
    text = re.sub(r"</\s*p\s*>", "\n\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def send_custom_mail_admin(*, subject: str, html: str, recipient_mode: str, email: str = "") -> dict:
    from email_service import send_email_async
    from auth_service import _email_ok

    subject = (subject or "").strip()
    if not subject:
        raise HTTPException(400, "Subject is required")
    mode = (recipient_mode or "single").strip().lower()
    recipients: list[str] = []
    with get_db() as db:
        if mode == "all":
            recipients = [u.email for u in db.query(User).filter(User.is_active == True).all() if u.email]
        else:
            email_l = (email or "").strip().lower()
            if not _email_ok(email_l):
                raise HTTPException(400, "Enter a valid recipient email")
            recipients = [email_l]
    safe_html = _sanitize_mail_html(html)
    text = _html_to_text(safe_html)
    for recipient in recipients:
        send_email_async(recipient, subject, safe_html, text)
    return {"sent": len(recipients), "skipped": 0, "mode": mode}


def list_monitors_admin() -> dict:
    with get_db() as db:
        rows = db.query(Monitor).order_by(Monitor.last_checked.desc()).all()
        items = [{
            "monitor_id": m.monitor_id,
            "target": m.target[:120],
            "target_type": m.target_type,
            "frequency": m.frequency,
            "last_checked": m.last_checked,
            "last_score": m.last_score,
            "alert_email": m.alert_email,
            "is_active": m.is_active,
        } for m in rows]
    return {"monitors": items, "total": len(items)}


def list_flagged_scans(*, page: int = 1, limit: int = 30) -> dict:
    """Return scans where the saved report flagged `needs_manual_review`.
    This does a lightweight text search in `findings_json` for the flag.
    """
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    with get_db() as db:
        query = db.query(Scan).filter(Scan.findings_json.ilike('%"needs_manual_review"%'))
        total = query.count()
        rows = query.order_by(Scan.timestamp.desc()).offset((page - 1) * limit).limit(limit).all()
        items = []
        for r in rows:
            try:
                data = json.loads(r.findings_json or "{}")
            except Exception:
                data = {}
            items.append({
                "scan_id": r.scan_id,
                "scan_type": r.scan_type,
                "target": r.target[:200],
                "score": r.score,
                "grade": r.grade,
                "timestamp": r.timestamp,
                "report": data,
            })
    return {"items": items, "total": total, "page": page, "limit": limit}


def list_llm_calls(*, page: int = 1, limit: int = 50, scan_id: str = "") -> dict:
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    from database import LLMCall
    with get_db() as db:
        query = db.query(LLMCall)
        if scan_id:
            like = f'%"scan_id": "{scan_id}"%'
            query = query.filter(LLMCall.meta_json.ilike(like))
        total = query.count()
        rows = query.order_by(LLMCall.timestamp.desc()).offset((page - 1) * limit).limit(limit).all()
        items = [{
            "call_id": r.call_id,
            "timestamp": r.timestamp,
            "provider": r.provider,
            "model": r.model,
            "prompt": r.prompt,
            "response": r.response,
            "parsed_json": json.loads(r.parsed_json or "{}"),
            "meta": json.loads(r.meta_json or "{}"),
        } for r in rows]
    return {"items": items, "total": total, "page": page, "limit": limit}


def mark_scan_reviewed(scan_id: str, reviewer_id: str, note: str = "") -> dict:
    """Mark a flagged scan as reviewed and attach reviewer note."""
    from database import get_db, Scan
    with get_db() as db:
        row = db.query(Scan).filter(Scan.scan_id == scan_id).first()
        if not row:
            raise HTTPException(404, "Scan not found")
        try:
            data = json.loads(row.findings_json or "{}")
        except Exception:
            data = {}
        data["needs_manual_review"] = False
        data["reviewed_by"] = reviewer_id or ""
        data["reviewed_at"] = int(time.time())
        if note:
            data["review_note"] = note[:2000]
        row.findings_json = json.dumps(data)
        row.updated_at = int(time.time()) if hasattr(row, 'updated_at') else int(time.time())
    return {"scan_id": scan_id, "reviewed_by": reviewer_id, "note": note}


def admin_upgrade_user(user_id: str, plan_id: str = "premium_monthly") -> dict:
    with get_db() as db:
        row = db.query(User).filter(User.user_id == user_id).first()
        if not row:
            raise HTTPException(404, "User not found")
        if plan_id in ("premium", "premium_monthly"):
            raise HTTPException(410, "Billing and paid plan activation are disabled on this deployment.")
        elif plan_id == "free":
            # Map legacy 'free' action to expired state (no active trial/premium)
            row.plan = "expired"
            row.subscription_status = "cancelled"
            row.premium_until = 0
        elif plan_id in ("trial", "account"):
            row.plan = "account"
            row.trial_ends_at = 0
        else:
            row.plan = plan_id[:30]
        row.updated_at = int(time.time())
    return get_user_admin(user_id)


def paystack_admin_status() -> dict:
    from billing_service import paystack_configured, paystack_status
    return {"paystack_enabled": paystack_configured(), "paystack_status": paystack_status()}


def admin_charts_data() -> dict:
    """Time-series and breakdown data for admin ERP charts."""
    import datetime

    now = int(time.time())
    days = 30
    day_buckets = []
    for i in range(days - 1, -1, -1):
        d = datetime.datetime.utcnow().date() - datetime.timedelta(days=i)
        day_buckets.append(d.isoformat())

    def bucket_ts(ts: int) -> str:
        if not ts:
            return ""
        return datetime.datetime.utcfromtimestamp(ts).date().isoformat()

    signups = {d: 0 for d in day_buckets}
    scans = {d: 0 for d in day_buckets}

    with get_db() as db:
        since = now - days * 86400
        for u in db.query(User).filter(User.created_at >= since).all():
            b = bucket_ts(u.created_at)
            if b in signups:
                signups[b] += 1
        for s in db.query(Scan).filter(Scan.timestamp >= since).all():
            b = bucket_ts(s.timestamp)
            if b in scans:
                scans[b] += 1

        plan_rows = (
            db.query(User.plan, func.count(User.user_id))
            .filter(User.is_active == True)
            .group_by(User.plan)
            .all()
        )
        plans = {str(p or "trial"): int(c) for p, c in plan_rows}
        premium_n = plans.get("premium", 0)
        # Pricing may be disabled in this deployment; handle missing keys safely.
        try:
            from pricing import PLANS
            price_ngn = int((PLANS.get("premium_monthly") or {}).get("price_ngn") or 0)
        except Exception:
            price_ngn = 0
        mrr_ngn = premium_n * price_ngn

    return {
        "labels": day_buckets,
        "signups_per_day": [signups[d] for d in day_buckets],
        "scans_per_day": [scans[d] for d in day_buckets],
        "users_by_plan": plans,
        "estimated_mrr_ngn": mrr_ngn,
        "premium_subscribers": premium_n,
    }
