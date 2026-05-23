"""Plan limits, module access, and usage quotas."""

import time
from typing import Optional

TRIAL_DAYS = 14

# Modules available on free tier (after trial ends)
FREE_MODULES = {
    "website",
    "email",
    "sandbox",
}

PREMIUM_MODULES = {
    "organization",
    "company",
    "auth",
    "monitor",
    "templates",
    "graph",
    "vulnerability",
    "subdomains",
    "ip",
    "person",
    "domain",
}

PLAN_LIMITS = {
    "free": {"hourly": 30, "monthly": 50, "max_keys": 1},
    "trial": {"hourly": 120, "monthly": 200, "max_keys": 2},
    "premium": {"hourly": 500, "monthly": 2000, "max_keys": 10},
    "sandbox": {"hourly": 9999, "monthly": 99999, "max_keys": 3},
}

MODULE_MONTHLY_CAPS = {
    "free": {
        "website": 10,
        "vulnerability": 10,
        "subdomains": 5,
        "ip": 10,
        "person": 5,
        "email": 10,
        "domain": 10,
        "sandbox": 20,
    },
    "trial": {m: 50 for m in list(FREE_MODULES | PREMIUM_MODULES | {"sandbox"})},
    "premium": {m: 500 for m in list(FREE_MODULES | PREMIUM_MODULES | {"sandbox"})},
}


def effective_plan(user: dict) -> str:
    now = int(time.time())
    if user.get("plan") == "premium":
        status = (user.get("subscription_status") or "").strip()
        until = int(user.get("premium_until") or 0)
        if status not in ("past_due", "expired", "cancelled") and (until == 0 or until > now):
            return "premium"
    if (user.get("trial_ends_at") or 0) > now:
        return "trial"
    return "free"


def can_access_module(user: Optional[dict], module: str) -> tuple[bool, str]:
    if module == "sandbox":
        return True, ""
    if not user:
        return False, "Create an account and sign in to run scans"
    plan = effective_plan(user)
    if plan in ("trial", "premium"):
        return True, ""
    if module in PREMIUM_MODULES:
        return False, "Premium feature — upgrade or use your free trial"
    if module in FREE_MODULES:
        return True, ""
    return False, "Module not available on your plan"


def get_limits(plan: str) -> dict:
    return PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])


def module_cap(plan: str, module: str) -> int:
    caps = MODULE_MONTHLY_CAPS.get(plan, MODULE_MONTHLY_CAPS["free"])
    return caps.get(module, caps.get("website", 10))
