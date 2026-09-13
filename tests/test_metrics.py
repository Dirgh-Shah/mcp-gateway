import pytest

from app.metrics import (
    LATENCY_BUCKETS,
    OUTCOME_ALLOWED,
    OUTCOME_DENIED,
    MetricsError,
    MetricsRegistry,
)


def lines(registry):
    return registry.render().splitlines()


def test_counters_start_at_zero_and_increment():
    registry = MetricsRegistry()
    assert 'mcpg_requests_total{outcome="allowed"} 0' in lines(registry)
    registry.increment_request(OUTCOME_ALLOWED)
    registry.increment_request(OUTCOME_ALLOWED)
    registry.increment_request(OUTCOME_DENIED)
    rendered = lines(registry)
    assert 'mcpg_requests_total{outcome="allowed"} 2' in rendered
    assert 'mcpg_requests_total{outcome="denied"} 1' in rendered


def test_unknown_outcome_raises_rather_than_being_dropped():
    with pytest.raises(MetricsError):
        MetricsRegistry().increment_request("something_else")


def test_every_metric_has_help_and_type_lines():
    rendered = MetricsRegistry().render()
    for name in (
        "mcpg_requests_total",
        "mcpg_scanner_findings_total",
        "mcpg_upstream_latency_seconds",
    ):
        assert f"# HELP {name} " in rendered
        assert f"# TYPE {name} " in rendered


def test_histogram_buckets_are_cumulative_and_end_with_inf():
    registry = MetricsRegistry()
    for value in (0.001, 0.03, 0.4, 12.0):
        registry.observe_upstream_latency(value)
    rendered = lines(registry)

    assert f'mcpg_upstream_latency_seconds_bucket{{le="{LATENCY_BUCKETS[0]}"}} 1' in rendered
    assert 'mcpg_upstream_latency_seconds_bucket{le="+Inf"} 4' in rendered
    assert "mcpg_upstream_latency_seconds_count 4" in rendered

    bucket_values = [
        int(line.rsplit(" ", 1)[1])
        for line in rendered
        if line.startswith("mcpg_upstream_latency_seconds_bucket")
    ]
    assert bucket_values == sorted(bucket_values)


def test_histogram_sum_is_the_total_observed():
    registry = MetricsRegistry()
    registry.observe_upstream_latency(0.25)
    registry.observe_upstream_latency(0.75)
    total = next(
        float(line.rsplit(" ", 1)[1])
        for line in lines(registry)
        if line.startswith("mcpg_upstream_latency_seconds_sum")
    )
    assert total == pytest.approx(1.0)


def test_negative_latency_raises():
    with pytest.raises(MetricsError):
        MetricsRegistry().observe_upstream_latency(-0.1)


def test_findings_are_labelled_by_detector_and_severity():
    registry = MetricsRegistry()
    registry.increment_finding("aws_access_key_id", "high", 2)
    assert (
        'mcpg_scanner_findings_total{detector="aws_access_key_id",severity="high"} 2'
        in lines(registry)
    )


def test_render_ends_with_a_newline():
    assert MetricsRegistry().render().endswith("\n")
