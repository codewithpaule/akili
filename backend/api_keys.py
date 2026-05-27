import hashlib
import secrets
import time
import uuid
from typing import Optional

from database import ApiKey, get_db
from plans import PLAN_LIMITS, effective_plan, get_limits

TIER_LIMITS = {
    "browser": 10,
    "account": PLAN_LIMITS.get("account", {}).get("hourly", 120),
    "trial": PLAN_LIMITS.get("trial", {}).get("hourly", 120),
    "premium": PLAN_LIMITS.get("premium", {}).get("hourly", 500),
    "pro": 500,
    "business": 2000,
    "sandbox": PLAN_LIMITS.get("sandbox", {}).get("hourly", 9999),
}


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _preview(raw: str) -> str:
    if len(raw) < 16:
        return raw[:4] + "..." + raw[-4:]
    return raw[:12] + "..." + raw[-4:]


def generate_api_key(user_id: str, user: dict, *, sandbox: bool = False, name: str = "") -> dict:
    label = (name or "").strip()[:80]
    if not label:
        raise ValueError("API key name is required")
    plan = effective_plan(user)
    limits = get_limits("sandbox" if sandbox else plan)
    max_keys = limits["max_keys"]

    with get_db() as db:
        active = db.query(ApiKey).filter(ApiKey.user_id == user_id, ApiKey.is_active == True).count()
        if active >= max_keys:
            raise ValueError(f"Maximum {max_keys} API key(s) on your plan")

    prefix = "ak_test_" if sandbox else "ak_live_"
    raw = prefix + secrets.token_urlsafe(24)
    key_id = str(uuid.uuid4())
    now = int(time.time())
    tier = "sandbox" if sandbox else plan

    with get_db() as db:
        db.add(ApiKey(
            key_id=key_id,
            user_id=user_id,
            key_name=label,
            key_hash=_hash_key(raw),
            key_preview=_preview(raw),
            tier=tier,
            created_at=now,
            last_used=0,
            requests_today=0,
            requests_month=0,
            is_sandbox=sandbox,
            is_active=True,
        ))

    return {
        "key_id": key_id,
        "name": label,
        "api_key": raw,
        "tier": tier,
        "preview": _preview(raw),
        "message": "Store this safely — it will not be shown again.",
    }


def lookup_api_key(header_value: Optional[str], increment_usage: bool = False) -> Optional[dict]:
    if not header_value or not header_value.strip():
        return None
    h = _hash_key(header_value.strip())
    with get_db() as db:
        row = db.query(ApiKey).filter(ApiKey.key_hash == h, ApiKey.is_active == True).first()
        if not row:
            return None
        if increment_usage:
            row.last_used = int(time.time())
            row.requests_today = (row.requests_today or 0) + 1
            row.requests_month = (row.requests_month or 0) + 1
        tier = row.tier or "account"
        return {
            "key_id": row.key_id,
            "user_id": row.user_id or "",
            "tier": "sandbox" if row.is_sandbox else tier,
            "is_sandbox": row.is_sandbox,
            "limit": TIER_LIMITS.get("sandbox" if row.is_sandbox else tier, 50),
            "requests_today": row.requests_today or 0,
            "requests_month": row.requests_month or 0,
        }


def resolve_api_key(header_value: Optional[str]) -> Optional[dict]:
    return lookup_api_key(header_value, increment_usage=True)


def _key_usage_fields(row: ApiKey) -> dict:
    tier = row.tier or "account"
    sandbox = bool(row.is_sandbox)
    hourly_limit = TIER_LIMITS["sandbox"] if sandbox else TIER_LIMITS.get(tier, TIER_LIMITS.get("trial", 120))
    calls_today = row.requests_today or 0
    calls_month = row.requests_month or 0
    return {
        "hourly_limit": hourly_limit,
        "api_calls_today": calls_today,
        "api_calls_month": calls_month,
        "hourly_remaining": max(0, hourly_limit - calls_today),
        "last_used_at": row.last_used or 0,
    }


def list_keys_for_user(user_id: str):
    with get_db() as db:
        rows = (
            db.query(ApiKey)
            .filter(ApiKey.user_id == user_id, ApiKey.is_active == True)
            .order_by(ApiKey.created_at.desc())
            .all()
        )
        out = []
        for r in rows:
            item = {
                "key_id": r.key_id,
                "name": r.key_name or "",
                "key_preview": r.key_preview,
                "tier": r.tier,
                "created_at": r.created_at,
                "last_used": r.last_used,
                "requests_today": r.requests_today,
                "requests_month": r.requests_month,
                "is_sandbox": r.is_sandbox,
            }
            item.update(_key_usage_fields(r))
            out.append(item)
        return out


def list_keys_masked():
    with get_db() as db:
        rows = db.query(ApiKey).filter(ApiKey.is_active == True).order_by(ApiKey.created_at.desc()).limit(100).all()
        return [{
            "key_id": r.key_id,
            "name": r.key_name or "",
            "key_preview": r.key_preview,
            "tier": r.tier,
            "created_at": r.created_at,
            "last_used": r.last_used,
            "requests_today": r.requests_today,
            "requests_month": r.requests_month,
            "is_sandbox": r.is_sandbox,
        } for r in rows]


def revoke_key(key_id: str, user_id: Optional[str] = None) -> bool:
    with get_db() as db:
        q = db.query(ApiKey).filter(ApiKey.key_id == key_id)
        if user_id:
            q = q.filter(ApiKey.user_id == user_id)
        row = q.first()
        if not row:
            return False
        row.is_active = False
        return True
