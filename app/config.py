"""Process configuration.

Every tunable value the gateway uses is defined here once and imported
elsewhere. Nothing in this module falls back to an insecure default: a missing
or weak signing secret raises rather than being papered over.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

# --- shared constants (single source of truth) -------------------------------

#: Minimum acceptable length of MCPG_SIGNING_SECRET, in characters.
MIN_SIGNING_SECRET_LENGTH = 32

#: Prefix of every issued API key: mcpg_<key_id>_<secret>.
KEY_PREFIX = "mcpg"

#: Length of the hex key id embedded in an API key.
KEY_ID_LENGTH = 12

#: Number of random bytes behind the secret half of an API key.
KEY_SECRET_BYTES = 32

DEFAULT_RATE_LIMIT_RPM = 60
DEFAULT_RATE_LIMIT_BURST = 10
DEFAULT_UPSTREAM_TIMEOUT_SECONDS = 10.0

#: Scanner modes, in increasing order of strictness.
SCANNER_MODES = ("off", "redact", "block")

#: Severity levels a scanner finding may carry. Only HIGH triggers block mode.
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITIES = (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH)


class ConfigError(RuntimeError):
    """Raised when the environment cannot produce a usable configuration."""


@dataclass(frozen=True)
class Settings:
    signing_secret: str
    policy_file: str
    keys_file: str
    audit_db: str
    scanner_mode: str
    rate_limit_rpm: int
    rate_limit_burst: int
    upstream_timeout_seconds: float


def _require(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(
            f"{name} is required and unset. Refusing to start; see .env.example."
        )
    return value


def _int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be positive, got {value}")
    return value


def _float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be positive, got {value}")
    return value


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Build Settings from a mapping, defaulting to os.environ.

    Raises ConfigError rather than returning a partially valid object.
    """
    env = os.environ if env is None else env

    signing_secret = _require(env, "MCPG_SIGNING_SECRET")
    if len(signing_secret) < MIN_SIGNING_SECRET_LENGTH:
        raise ConfigError(
            f"MCPG_SIGNING_SECRET must be at least {MIN_SIGNING_SECRET_LENGTH} "
            f"characters, got {len(signing_secret)}. Refusing to start."
        )

    scanner_mode = (env.get("MCPG_SCANNER_MODE") or "redact").strip().lower()
    if scanner_mode not in SCANNER_MODES:
        raise ConfigError(
            f"MCPG_SCANNER_MODE must be one of {', '.join(SCANNER_MODES)}, "
            f"got {scanner_mode!r}"
        )

    settings = Settings(
        signing_secret=signing_secret,
        policy_file=env.get("MCPG_POLICY_FILE") or "policy.yaml",
        keys_file=env.get("MCPG_KEYS_FILE") or "keys.json",
        audit_db=env.get("MCPG_AUDIT_DB") or "audit.db",
        scanner_mode=scanner_mode,
        rate_limit_rpm=_int(env, "MCPG_RATE_LIMIT_RPM", DEFAULT_RATE_LIMIT_RPM),
        rate_limit_burst=_int(env, "MCPG_RATE_LIMIT_BURST", DEFAULT_RATE_LIMIT_BURST),
        upstream_timeout_seconds=_float(
            env, "MCPG_UPSTREAM_TIMEOUT_SECONDS", DEFAULT_UPSTREAM_TIMEOUT_SECONDS
        ),
    )
    return settings
