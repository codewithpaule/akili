"""Simple per-domain async rate limiter for crawlers."""
import asyncio
import time
from collections import defaultdict

# Map domain -> (semaphore, last_request_ts)
_domain_state: dict[str, dict] = {}


def _get_domain_state(domain: str):
    if domain not in _domain_state:
        _domain_state[domain] = {"lock": asyncio.Lock(), "last": 0.0}
    return _domain_state[domain]


async def rate_limit_domain(domain: str, min_interval: float = 0.5):
    """Ensure we wait at least `min_interval` seconds between requests to `domain`.

    Usage: await rate_limit_domain("example.com", 0.5)
    """
    st = _get_domain_state(domain)
    async with st["lock"]:
        now = time.time()
        wait = min_interval - (now - st["last"])
        if wait > 0:
            await asyncio.sleep(wait)
        st["last"] = time.time()
