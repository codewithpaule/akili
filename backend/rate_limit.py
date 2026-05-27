import time
from typing import Optional

from slowapi import Limiter
from slowapi.util import get_remote_address

from api_keys import TIER_LIMITS, lookup_api_key

limiter = Limiter(key_func=get_remote_address)


def get_tier_from_request(request) -> tuple[str, int, bool]:
    """Returns (tier_name, hourly_limit, is_sandbox)."""
    api_key = request.headers.get("X-API-Key") or request.headers.get("x-api-key")
    if not api_key:
        return "browser", TIER_LIMITS["browser"], False

    resolved = lookup_api_key(api_key, increment_usage=False)
    if resolved:
        if resolved.get("is_sandbox"):
            return "sandbox", TIER_LIMITS["sandbox"], True
        tier = resolved.get("tier", "trial")
        return tier, TIER_LIMITS.get(tier, 50), False
    return "browser", TIER_LIMITS["browser"], False


def rate_limit_headers(tier: str, limit: int, remaining: int) -> dict:
    reset_at = int(time.time()) + 3600
    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(0, remaining)),
        "X-RateLimit-Reset": str(reset_at),
        "X-AKILI-Tier": tier,
    }
