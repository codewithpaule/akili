"""Run async coroutines from sync code (safe under uvicorn/FastAPI)."""

import asyncio
import concurrent.futures


def run_async(coro, timeout: float = 90):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result(timeout=timeout)
