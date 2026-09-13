import pytest

from app.config import (
    DEFAULT_RATE_LIMIT_RPM,
    MIN_SIGNING_SECRET_LENGTH,
    ConfigError,
    load_settings,
)

GOOD_SECRET = "x" * MIN_SIGNING_SECRET_LENGTH


def test_missing_signing_secret_refuses_to_start():
    with pytest.raises(ConfigError):
        load_settings({})


def test_blank_signing_secret_refuses_to_start():
    with pytest.raises(ConfigError):
        load_settings({"MCPG_SIGNING_SECRET": "   "})


def test_short_signing_secret_refuses_to_start():
    with pytest.raises(ConfigError):
        load_settings({"MCPG_SIGNING_SECRET": "x" * (MIN_SIGNING_SECRET_LENGTH - 1)})


def test_no_default_signing_secret_exists():
    settings = load_settings({"MCPG_SIGNING_SECRET": GOOD_SECRET})
    assert settings.signing_secret == GOOD_SECRET


def test_defaults_are_applied_for_optional_values():
    settings = load_settings({"MCPG_SIGNING_SECRET": GOOD_SECRET})
    assert settings.policy_file == "policy.yaml"
    assert settings.keys_file == "keys.json"
    assert settings.audit_db == "audit.db"
    assert settings.scanner_mode == "redact"
    assert settings.rate_limit_rpm == DEFAULT_RATE_LIMIT_RPM


def test_unknown_scanner_mode_is_rejected():
    with pytest.raises(ConfigError):
        load_settings({"MCPG_SIGNING_SECRET": GOOD_SECRET, "MCPG_SCANNER_MODE": "loud"})


def test_non_numeric_rate_limit_is_rejected():
    with pytest.raises(ConfigError):
        load_settings({"MCPG_SIGNING_SECRET": GOOD_SECRET, "MCPG_RATE_LIMIT_RPM": "many"})


def test_non_positive_rate_limit_is_rejected():
    with pytest.raises(ConfigError):
        load_settings({"MCPG_SIGNING_SECRET": GOOD_SECRET, "MCPG_RATE_LIMIT_RPM": "0"})


def test_overrides_are_read_from_the_environment_mapping():
    settings = load_settings(
        {
            "MCPG_SIGNING_SECRET": GOOD_SECRET,
            "MCPG_SCANNER_MODE": "block",
            "MCPG_RATE_LIMIT_RPM": "120",
            "MCPG_RATE_LIMIT_BURST": "20",
            "MCPG_UPSTREAM_TIMEOUT_SECONDS": "2.5",
        }
    )
    assert settings.scanner_mode == "block"
    assert settings.rate_limit_rpm == 120
    assert settings.rate_limit_burst == 20
    assert settings.upstream_timeout_seconds == 2.5
