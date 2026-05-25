"""Per-user module access and monthly usage enforcement."""

from fastapi import HTTPException

from database import count_user_keys, get_usage_summary, increment_usage
from plans import can_access_module, effective_plan, get_limits, module_cap

PLAN_LABELS = {"trial": "Trial", "premium": "Premium", "expired": "Expired"}


def enforce_scan_access(user: dict | None, module: str, *, sandbox: bool = False) -> None:
    if sandbox:
        return
    mod = module
    ok, msg = can_access_module(user, mod)
    if not ok:
        raise HTTPException(403, msg or "Module not available on your plan")

    if not user:
        return

    plan = effective_plan(user)
    usage = get_usage_summary(user["user_id"])
    cap = module_cap(plan, mod)
    used = usage.get(mod, 0)
    if used >= cap:
        raise HTTPException(
            429,
            f"Monthly limit for {mod} reached ({cap}). Upgrade to Premium for higher limits.",
        )
    increment_usage(user["user_id"], mod)


def usage_payload(user: dict) -> dict:
    plan = effective_plan(user)
    limits = get_limits(plan)
    usage = get_usage_summary(user["user_id"])
    caps = {m: module_cap(plan, m) for m in set(list(usage.keys()) + ["website", "person", "sandbox"])}
    monthly_used = sum(usage.values())
    key_count = count_user_keys(user["user_id"])
    return {
        "plan": plan,
        "plan_label": PLAN_LABELS.get(plan, plan.title()),
        "trial_ends_at": user.get("trial_ends_at"),
        "hourly_limit": limits["hourly"],
        "monthly_total_limit": limits["monthly"],
        "monthly_scans_used": monthly_used,
        "monthly_scans_remaining": max(0, limits["monthly"] - monthly_used),
        "active_api_keys": key_count,
        "max_api_keys": limits["max_keys"],
        "usage_this_month": usage,
        "module_caps": caps,
    }
