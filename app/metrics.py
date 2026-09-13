"""Prometheus text exposition, written by hand.

The format is simple enough that a dependency is not worth its weight: counters
are a name, optional labels and a number; a histogram is a set of cumulative
buckets plus a sum and a count. Roughly eighty lines, no supply chain.
"""

from __future__ import annotations

import threading
from typing import Iterable

#: Outcomes a request can end in. Every request increments exactly one.
OUTCOME_ALLOWED = "allowed"
OUTCOME_DENIED = "denied"
OUTCOME_RATE_LIMITED = "rate_limited"
OUTCOME_BLOCKED = "blocked"
OUTCOME_UNAUTHENTICATED = "unauthenticated"
OUTCOME_UPSTREAM_ERROR = "upstream_error"

OUTCOMES = (
    OUTCOME_ALLOWED,
    OUTCOME_DENIED,
    OUTCOME_RATE_LIMITED,
    OUTCOME_BLOCKED,
    OUTCOME_UNAUTHENTICATED,
    OUTCOME_UPSTREAM_ERROR,
)

#: Upper bounds in seconds. The +Inf bucket is appended at render time.
LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class MetricsError(RuntimeError):
    pass


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[str, int] = {outcome: 0 for outcome in OUTCOMES}
        self._findings: dict[tuple[str, str], int] = {}
        self._latency_counts: list[int] = [0] * (len(LATENCY_BUCKETS) + 1)
        self._latency_sum: float = 0.0
        self._latency_total: int = 0

    def increment_request(self, outcome: str) -> None:
        if outcome not in self._requests:
            raise MetricsError(f"unknown request outcome {outcome!r}")
        with self._lock:
            self._requests[outcome] += 1

    def increment_finding(self, detector: str, severity: str, count: int = 1) -> None:
        if count <= 0:
            raise MetricsError("finding count must be positive")
        with self._lock:
            key = (detector, severity)
            self._findings[key] = self._findings.get(key, 0) + count

    def observe_upstream_latency(self, seconds: float) -> None:
        if seconds < 0:
            raise MetricsError(f"latency must be non-negative, got {seconds}")
        with self._lock:
            index = len(LATENCY_BUCKETS)
            for i, bound in enumerate(LATENCY_BUCKETS):
                if seconds <= bound:
                    index = i
                    break
            self._latency_counts[index] += 1
            self._latency_sum += seconds
            self._latency_total += 1

    def render(self) -> str:
        with self._lock:
            lines: list[str] = []
            lines.extend(self._render_requests())
            lines.extend(self._render_findings())
            lines.extend(self._render_latency())
            return "\n".join(lines) + "\n"

    # -- renderers ------------------------------------------------------------

    def _render_requests(self) -> Iterable[str]:
        yield "# HELP mcpg_requests_total Tool call requests by final outcome."
        yield "# TYPE mcpg_requests_total counter"
        for outcome in OUTCOMES:
            yield (
                f'mcpg_requests_total{{outcome="{_escape(outcome)}"}} '
                f"{self._requests[outcome]}"
            )

    def _render_findings(self) -> Iterable[str]:
        yield "# HELP mcpg_scanner_findings_total Scanner matches by detector."
        yield "# TYPE mcpg_scanner_findings_total counter"
        for (detector, severity), count in sorted(self._findings.items()):
            yield (
                f'mcpg_scanner_findings_total{{detector="{_escape(detector)}",'
                f'severity="{_escape(severity)}"}} {count}'
            )

    def _render_latency(self) -> Iterable[str]:
        yield "# HELP mcpg_upstream_latency_seconds Upstream call latency."
        yield "# TYPE mcpg_upstream_latency_seconds histogram"
        cumulative = 0
        for bound, count in zip(LATENCY_BUCKETS, self._latency_counts):
            cumulative += count
            yield f'mcpg_upstream_latency_seconds_bucket{{le="{bound}"}} {cumulative}'
        cumulative += self._latency_counts[-1]
        yield f'mcpg_upstream_latency_seconds_bucket{{le="+Inf"}} {cumulative}'
        yield f"mcpg_upstream_latency_seconds_sum {self._latency_sum!r}"
        yield f"mcpg_upstream_latency_seconds_count {self._latency_total}"
