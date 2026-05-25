"""Plan limits, module access, and usage quotas."""

import time
from typing import Optional

TRIAL_DAYS = 14

# Previously there was a 'free' tier after trial — remove it.
# Only 'trial' and 'premium' are considered active plans. After trial ends
# users are treated as 'expired' and blocked from running modules until they upgrade.
FREE_MODULES = set()

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
    "api",
}

PLAN_LIMITS = {
    "trial": {"hourly": 120, "monthly": 200, "max_keys": 2},
    "premium": {"hourly": 500, "monthly": 2000, "max_keys": 10},
    "sandbox": {"hourly": 9999, "monthly": 99999, "max_keys": 3},
}

MODULE_MONTHLY_CAPS = {
    "trial": {m: 50 for m in list(PREMIUM_MODULES | {"sandbox"})},
    "premium": {m: 500 for m in list(PREMIUM_MODULES | {"sandbox"})},
}


def effective_plan(user: dict) -> str:
    now = int(time.time())
    if user.get("plan") == "premium":
        status = (user.get("subscription_status") or "").strip()
        until = int(user.get("premium_until") or 0)
        if status not in ("past_due", "expired", "cancelled") and (until == 0 or until > now):
            return "premium"
    # If trial still active, return 'trial'. After trial ends, return 'expired'
    if (user.get("trial_ends_at") or 0) > now:
        return "trial"
    return "expired"


def can_access_module(user: Optional[dict], module: str) -> tuple[bool, str]:
    # Only trial and premium users may run modules. Sandbox remains a special case only
    # for local/dev usage if enabled via other guards.
    if not user:
        return False, "Create an account and sign in to run scans"
    plan = effective_plan(user)
    if plan in ("trial", "premium"):
        return True, ""
    return False, "Your trial has ended — upgrade to Premium to run scans"


def get_limits(plan: str) -> dict:
    return PLAN_LIMITS.get(plan, PLAN_LIMITS.get("trial", {}))


def module_cap(plan: str, module: str) -> int:
    caps = MODULE_MONTHLY_CAPS.get(plan, MODULE_MONTHLY_CAPS["trial"])
    return caps.get(module, caps.get("website", 10))
