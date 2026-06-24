"""Simple in-memory TTL cache for expensive external API calls."""

import time
from typing import Any

_store: dict[str, dict] = {}


def cache_get(key: str) -> Any | None:
    entry = _store.get(key)
    if entry and time.time() < entry["expires"]:
        return entry["value"]
    if entry:
        del _store[key]
    return None


def cache_set(key: str, value: Any, ttl_seconds: int = 300) -> None:
    _store[key] = {"value": value, "expires": time.time() + ttl_seconds}


def cache_key(*parts: str) -> str:
    return ":".join(str(p).lower().strip() for p in parts if p)
