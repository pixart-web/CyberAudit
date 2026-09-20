"""Bounded HTTP load smoke test. Run only against an explicitly supplied local URL."""

from __future__ import annotations

import asyncio
import os
import statistics
import time
from urllib.parse import urlparse

import httpx


async def main() -> None:
    url = os.environ.get("LOAD_TEST_URL", "http://127.0.0.1:8000/health")
    parsed = urlparse(url)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise SystemExit("LOAD_TEST_URL must target localhost")
    requests = min(int(os.environ.get("LOAD_TEST_REQUESTS", "200")), 2000)
    concurrency = min(int(os.environ.get("LOAD_TEST_CONCURRENCY", "20")), 100)
    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []

    async with httpx.AsyncClient(timeout=5) as client:

        async def request() -> int:
            async with semaphore:
                started = time.perf_counter()
                response = await client.get(url)
                latencies.append((time.perf_counter() - started) * 1000)
                return response.status_code

        statuses = await asyncio.gather(*(request() for _ in range(requests)))
    ordered = sorted(latencies)
    p95 = ordered[max(0, int(len(ordered) * 0.95) - 1)]
    print(
        {
            "requests": requests,
            "successful": sum(status == 200 for status in statuses),
            "mean_ms": round(statistics.mean(latencies), 2),
            "p95_ms": round(p95, 2),
        }
    )
    if any(status != 200 for status in statuses):
        raise SystemExit("Load smoke test observed unsuccessful responses")


if __name__ == "__main__":
    asyncio.run(main())
