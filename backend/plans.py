"""Plan limits, module access, and usage quotas."""

import time
from typing import Optional

TRIAL_DAYS = 14

# Make the platform free for all users by default: non-premium users are treated
# as the baseline 'trial' tier with daily limits. Premium remains available.
FREE_MODULES = set()

PREMIUM_MODULES = set()

# Limits are enforced per-day while we run the service free. Adjust numbers as needed.
PLAN_LIMITS = {
    "trial": {"hourly": 120, "daily": 20, "max_keys": 2},
    "premium": {"hourly": 500, "daily": 200, "max_keys": 10},
    "sandbox": {"hourly": 9999, "daily": 99999, "max_keys": 3},
}

MODULE_DAILY_CAPS = {
    "trial": {m: 5 for m in list(PREMIUM_MODULES | {"sandbox"})},
    "premium": {m: 50 for m in list(PREMIUM_MODULES | {"sandbox"})},
}


def effective_plan(user: dict) -> str:
    now = int(time.time())
    if user.get("plan") == "premium":
        status = (user.get("subscription_status") or "").strip()
        until = int(user.get("premium_until") or 0)
        if status not in ("past_due", "expired", "cancelled") and (until == 0 or until > now):
            return "premium"
    # Treat all non-premium users as the free/trial tier so the platform remains usable
    return "trial"


def can_access_module(user: Optional[dict], module: str) -> tuple[bool, str]:
    # Only trial and premium users may run modules. Sandbox remains a special case only
    # for local/dev usage if enabled via other guards.
    if not user:
        return False, "Create an account and sign in to run scans"
    plan = effective_plan(user)
    if plan in ("trial", "premium"):
        return True, ""
    return False, "Your trial has ended — contact the administrator for higher limits or access"


def get_limits(plan: str) -> dict:
    return PLAN_LIMITS.get(plan, PLAN_LIMITS.get("trial", {}))


def module_cap(plan: str, module: str) -> int:
    caps = MODULE_DAILY_CAPS.get(plan, MODULE_DAILY_CAPS["trial"])
    return caps.get(module, caps.get("website", 5))
