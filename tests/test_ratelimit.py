import pytest

from app.ratelimit import RateLimiter


class FakeClock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_burst_is_allowed_then_further_calls_are_denied():
    clock = FakeClock()
    limiter = RateLimiter(requests_per_minute=60, burst=5, clock=clock)
    assert all(limiter.check("alice").allowed for _ in range(5))
    assert not limiter.check("alice").allowed


def test_tokens_refill_over_injected_time():
    clock = FakeClock()
    limiter = RateLimiter(requests_per_minute=60, burst=2, clock=clock)
    assert limiter.check("alice").allowed
    assert limiter.check("alice").allowed
    assert not limiter.check("alice").allowed

    clock.advance(1.0)  # 60 rpm is one token per second
    assert limiter.check("alice").allowed
    assert not limiter.check("alice").allowed


def test_refill_never_exceeds_the_burst_capacity():
    clock = FakeClock()
    limiter = RateLimiter(requests_per_minute=60, burst=3, clock=clock)
    for _ in range(3):
        assert limiter.check("alice").allowed
    clock.advance(3600.0)
    assert sum(limiter.check("alice").allowed for _ in range(10)) == 3


def test_retry_after_reflects_the_refill_rate():
    clock = FakeClock()
    limiter = RateLimiter(requests_per_minute=30, burst=1, clock=clock)
    assert limiter.check("alice").allowed
    decision = limiter.check("alice")
    assert not decision.allowed
    assert decision.retry_after_seconds == pytest.approx(2.0)


def test_principals_have_separate_buckets():
    clock = FakeClock()
    limiter = RateLimiter(requests_per_minute=60, burst=1, clock=clock)
    assert limiter.check("alice").allowed
    assert not limiter.check("alice").allowed
    assert limiter.check("bob").allowed


def test_invalid_configuration_raises():
    with pytest.raises(ValueError):
        RateLimiter(requests_per_minute=0, burst=1)
    with pytest.raises(ValueError):
        RateLimiter(requests_per_minute=60, burst=0)
