"""Shared HTTP clients with connection pooling for the entire application."""

import httpx

_client: httpx.AsyncClient | None = None
_sync_client: httpx.Client | None = None


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=2.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=True,
            headers={"User-Agent": "AKILI-Platform/2.0"},
        )
    return _client


def get_sync_client() -> httpx.Client:
    global _sync_client
    if _sync_client is None or _sync_client.is_closed:
        _sync_client = httpx.Client(
            timeout=httpx.Timeout(connect=5.0, read=15.0, write=5.0),
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=10),
            follow_redirects=True,
            headers={"User-Agent": "AKILI-Platform/2.0"},
        )
    return _sync_client


async def close_client() -> None:
    global _client, _sync_client
    if _client and not _client.is_closed:
        await _client.aclose()
    _client = None
    if _sync_client and not _sync_client.is_closed:
        _sync_client.close()
    _sync_client = None
