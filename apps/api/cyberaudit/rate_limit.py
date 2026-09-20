"""Distributed fixed-window rate limits for sensitive API entry points."""

from __future__ import annotations

import hashlib

import redis.asyncio as redis
from fastapi import HTTPException, Request

from cyberaudit.config import get_settings


async def enforce_rate_limit(
    request: Request,
    *,
    category: str,
    limit: int,
    window_seconds: int,
) -> None:
    settings = get_settings()
    source = request.client.host if request.client else "unknown"
    identity = hashlib.sha256(
        f"{settings.encryption_key}:{category}:{source}".encode()
    ).hexdigest()[:32]
    key = f"cyberaudit:rate:{category}:{identity}"
    client = redis.from_url(settings.redis_url, decode_responses=True)
    try:
        async with client.pipeline(transaction=True) as pipeline:
            pipeline.incr(key)
            pipeline.expire(key, window_seconds, nx=True)
            count, _ = await pipeline.execute()
    except (OSError, redis.RedisError) as exc:
        if settings.production_like:
            raise HTTPException(503, "Rate-limit service unavailable") from exc
        return
    finally:
        await client.aclose()
    if int(count) > limit:
        raise HTTPException(429, "Too many requests")
