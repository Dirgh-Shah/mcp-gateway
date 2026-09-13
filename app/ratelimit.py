"""Per-principal rate limiting.

A token bucket per principal: `requests_per_minute / 60` tokens accrue each
second, up to a burst capacity. The clock is injected so tests can advance time
instead of sleeping.

This is in-process state. Two gateway replicas will each allow a full budget;
see the limitations section of the README.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    remaining: float
    retry_after_seconds: float


class _Bucket:
    __slots__ = ("tokens", "updated_at")

    def __init__(self, tokens: float, updated_at: float):
        self.tokens = tokens
        self.updated_at = updated_at


class RateLimiter:
    def __init__(
        self,
        requests_per_minute: int,
        burst: int,
        clock: Callable[[], float] = time.monotonic,
    ):
        if requests_per_minute <= 0:
            raise ValueError("requests_per_minute must be positive")
        if burst <= 0:
            raise ValueError("burst must be positive")
        self.requests_per_minute = requests_per_minute
        self.burst = burst
        self.refill_per_second = requests_per_minute / 60.0
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}

    def _bucket(self, key: str) -> _Bucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=float(self.burst), updated_at=self._clock())
            self._buckets[key] = bucket
        return bucket

    def _refill(self, bucket: _Bucket) -> None:
        now = self._clock()
        elapsed = now - bucket.updated_at
        if elapsed > 0:
            bucket.tokens = min(
                float(self.burst), bucket.tokens + elapsed * self.refill_per_second
            )
            bucket.updated_at = now

    def check(self, key: str) -> RateDecision:
        """Consume one token for `key`, or report how long until one exists."""
        bucket = self._bucket(key)
        self._refill(bucket)

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return RateDecision(
                allowed=True, remaining=bucket.tokens, retry_after_seconds=0.0
            )

        deficit = 1.0 - bucket.tokens
        return RateDecision(
            allowed=False,
            remaining=bucket.tokens,
            retry_after_seconds=deficit / self.refill_per_second,
        )

    def reset(self, key: str | None = None) -> None:
        if key is None:
            self._buckets.clear()
        else:
            self._buckets.pop(key, None)
