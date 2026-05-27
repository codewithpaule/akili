"""Per-user module access and monthly usage enforcement."""

from fastapi import HTTPException

from database import check_and_increment_scan_limit, count_user_keys, get_daily_scan_count, get_usage_summary, increment_usage
from plans import ACCOUNT_DAILY_SCAN_LIMIT, can_access_module, effective_plan, get_limits, module_cap

PLAN_LABELS = {"account": "Account", "trial": "Account", "premium": "Account", "expired": "Expired"}


def usage_identity(user: dict) -> str:
    return user.get("usage_identity") or user.get("user_id", "")


def enforce_scan_access(user: dict | None, module: str, *, sandbox: bool = False) -> None:
    if sandbox:
        return
    mod = module
    ok, msg = can_access_module(user, mod)
    if not ok:
        raise HTTPException(403, msg or "Module not available on your plan")

    if not user:
        return

    identity = usage_identity(user)
    check_and_increment_scan_limit(identity)
    increment_usage(identity, mod)


def usage_payload(user: dict) -> dict:
    plan = effective_plan(user)
    limits = get_limits(plan)
    identity = usage_identity(user)
    usage = get_usage_summary(identity)
    caps = {m: module_cap(plan, m) for m in set(list(usage.keys()) + ["website", "person", "sandbox"]) }
    daily_used = get_daily_scan_count(identity)
    key_count = count_user_keys(user["user_id"])
    return {
        "plan": plan,
        "plan_label": PLAN_LABELS.get(plan, plan.title()),
        "trial_ends_at": user.get("trial_ends_at"),
        "hourly_limit": limits["hourly"],
        "daily_total_limit": limits.get("daily", limits.get("monthly", 0)),
        "daily_scans_used": daily_used,
        "daily_scans_remaining": max(0, ACCOUNT_DAILY_SCAN_LIMIT - daily_used),
        "active_api_keys": key_count,
        "max_api_keys": limits["max_keys"],
        "usage_today": usage,
        "module_caps": caps,
        "quota_model": "account_daily_total",
    }
