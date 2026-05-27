"""Plan limits, module access, and usage quotas."""

import time
from typing import Optional

TRIAL_DAYS = 0

# Normal accounts get one shared daily scan bucket. Legacy "trial" and
# "premium" values may still exist in old database rows, so we keep aliases
# below while presenting the product as a normal account.
FREE_MODULES = set()

PREMIUM_MODULES = set()

ACCOUNT_DAILY_SCAN_LIMIT = 5

PLAN_LIMITS = {
    "account": {"hourly": 120, "daily": ACCOUNT_DAILY_SCAN_LIMIT, "max_keys": 2},
    "trial": {"hourly": 120, "daily": ACCOUNT_DAILY_SCAN_LIMIT, "max_keys": 2},
    "premium": {"hourly": 120, "daily": ACCOUNT_DAILY_SCAN_LIMIT, "max_keys": 2},
    "sandbox": {"hourly": 9999, "daily": 99999, "max_keys": 3},
}

SCAN_MODULES = {"sandbox", "website", "email", "person", "domain", "ip", "organization", "company", "vulnerability", "subdomains", "api", "phone", "auth"}
MODULE_DAILY_CAPS = {
    "account": {m: ACCOUNT_DAILY_SCAN_LIMIT for m in SCAN_MODULES},
    "trial": {m: ACCOUNT_DAILY_SCAN_LIMIT for m in SCAN_MODULES},
    "premium": {m: ACCOUNT_DAILY_SCAN_LIMIT for m in SCAN_MODULES},
}


def effective_plan(user: dict) -> str:
    return "account"


def can_access_module(user: Optional[dict], module: str) -> tuple[bool, str]:
    # Only trial and premium users may run modules. Sandbox remains a special case only
    # for local/dev usage if enabled via other guards.
    if not user:
        return False, "Create an account and sign in to run scans"
    plan = effective_plan(user)
    if plan == "account":
        return True, ""
    return False, "Account access is unavailable. Please contact support."


def get_limits(plan: str) -> dict:
    return PLAN_LIMITS.get(plan, PLAN_LIMITS["account"])


def module_cap(plan: str, module: str) -> int:
    caps = MODULE_DAILY_CAPS.get(plan, MODULE_DAILY_CAPS["account"])
    return caps.get(module, ACCOUNT_DAILY_SCAN_LIMIT)
