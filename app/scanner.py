"""Outbound content inspection.

Tool results pass through here on the way back to the model. Two detector
families: credential patterns, and prompt-injection markers.

What this is honestly worth: the secret detectors are precise, because
credentials have fixed shapes. The injection detectors are not, and cannot be.
A regex cannot decide whether English text is an instruction aimed at a model.
They exist to catch the obvious cases and to put a record in the audit log, not
to guarantee anything. Treat a clean scan as "nothing obvious", never as "safe".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Pattern

from app.config import (
    SCANNER_MODES,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)

CATEGORY_SECRET = "secret"
CATEGORY_INJECTION = "injection"


class ScannerError(RuntimeError):
    """Raised on an unusable scanner configuration."""


@dataclass(frozen=True)
class Detector:
    name: str
    category: str
    severity: str
    pattern: Pattern[str]
    #: When set, only this capture group is replaced, so surrounding context
    #: (for example the literal `password=`) survives redaction.
    redact_group: int | None = None


@dataclass(frozen=True)
class Finding:
    """What is safe to log: the shape of what was found, never the value."""

    detector: str
    category: str
    severity: str
    count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "category": self.category,
            "severity": self.severity,
            "count": self.count,
        }


@dataclass(frozen=True)
class ScanResult:
    payload: Any
    findings: tuple[Finding, ...]
    blocked: bool
    mode: str

    @property
    def highest_severity(self) -> str | None:
        for severity in (SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW):
            if any(f.severity == severity for f in self.findings):
                return severity
        return None


SECRET_DETECTORS: tuple[Detector, ...] = (
    Detector(
        "aws_access_key_id",
        CATEGORY_SECRET,
        SEVERITY_HIGH,
        re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}\b"),
    ),
    Detector(
        "pem_private_key",
        CATEGORY_SECRET,
        SEVERITY_HIGH,
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
    ),
    Detector(
        "github_token",
        CATEGORY_SECRET,
        SEVERITY_HIGH,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    ),
    Detector(
        "slack_token",
        CATEGORY_SECRET,
        SEVERITY_HIGH,
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    Detector(
        "google_api_key",
        CATEGORY_SECRET,
        SEVERITY_HIGH,
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    Detector(
        "stripe_live_key",
        CATEGORY_SECRET,
        SEVERITY_HIGH,
        re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{16,}\b"),
    ),
    Detector(
        "jwt",
        CATEGORY_SECRET,
        SEVERITY_MEDIUM,
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ),
    Detector(
        "inline_password",
        CATEGORY_SECRET,
        SEVERITY_MEDIUM,
        # The keyword may be the tail of a longer identifier, as in
        # `registry_password=` or `AWS_SECRET_ACCESS_KEY:`, so no leading \b.
        re.compile(
            r"(?i)[A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|api[_-]?key)\s*[=:]\s*"
            r"[\"']?([^\s\"',;]{6,})"
        ),
        redact_group=1,
    ),
)

INJECTION_DETECTORS: tuple[Detector, ...] = (
    Detector(
        "instruction_override",
        CATEGORY_INJECTION,
        SEVERITY_HIGH,
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?\b"
            r"(?:previous|prior|earlier|above|all)\b[^.\n]{0,20}?\b"
            r"(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions)\b"
        ),
    ),
    Detector(
        "fake_tool_call",
        CATEGORY_INJECTION,
        SEVERITY_HIGH,
        re.compile(
            r"(?i)(?:<\s*/?\s*(?:tool_call|function_call|antml:invoke)\b"
            r"|\[\[\s*tool\s*:|\"tool_call\"\s*:)"
        ),
    ),
    Detector(
        "exfiltration_request",
        CATEGORY_INJECTION,
        SEVERITY_HIGH,
        re.compile(
            r"(?i)\b(?:send|post|upload|forward|exfiltrate|transmit)\b[^.\n]{0,60}?\b"
            r"(?:to\s+https?://|to\s+[\w.+-]+@[\w-]+\.[a-z]{2,}|webhook)"
        ),
    ),
    Detector(
        "system_prompt_probe",
        CATEGORY_INJECTION,
        SEVERITY_MEDIUM,
        re.compile(
            r"(?i)\b(?:reveal|repeat|print|show|output|dump)\b[^.\n]{0,40}?\b"
            r"(?:system prompt|system message|your instructions|initial prompt)\b"
        ),
    ),
    Detector(
        "role_reassignment",
        CATEGORY_INJECTION,
        SEVERITY_MEDIUM,
        re.compile(
            r"(?i)\byou are (?:now|actually)\b|\bnew (?:system )?instructions?\s*:"
            r"|\bdeveloper mode\b"
        ),
    ),
)

ALL_DETECTORS: tuple[Detector, ...] = SECRET_DETECTORS + INJECTION_DETECTORS


def placeholder_for(detector: Detector) -> str:
    return f"[REDACTED:{detector.name}]"


class Scanner:
    def __init__(
        self,
        mode: str = "redact",
        detectors: tuple[Detector, ...] = ALL_DETECTORS,
        redact_injection: bool = False,
    ):
        if mode not in SCANNER_MODES:
            raise ScannerError(
                f"mode must be one of {', '.join(SCANNER_MODES)}, got {mode!r}"
            )
        self.mode = mode
        self.detectors = detectors
        #: Injection markers are flagged but left in place by default: replacing
        #: arbitrary prose damages legitimate results, and the model still needs
        #: to see what it was sent. Turn this on to strip them as well.
        self.redact_injection = redact_injection

    # -- text level -----------------------------------------------------------

    def scan_text(self, text: str) -> tuple[str, dict[str, int]]:
        """Return (possibly redacted text, {detector name: match count})."""
        counts: dict[str, int] = {}
        result = text
        for detector in self.detectors:
            matches = list(detector.pattern.finditer(result))
            if not matches:
                continue
            counts[detector.name] = counts.get(detector.name, 0) + len(matches)

            should_redact = self.mode == "redact" and (
                detector.category == CATEGORY_SECRET or self.redact_injection
            )
            if not should_redact:
                continue

            if detector.redact_group is None:
                result = detector.pattern.sub(placeholder_for(detector), result)
            else:
                group = detector.redact_group
                pieces = []
                cursor = 0
                for match in detector.pattern.finditer(result):
                    start, end = match.span(group)
                    if start == -1:
                        continue
                    pieces.append(result[cursor:start])
                    pieces.append(placeholder_for(detector))
                    cursor = end
                pieces.append(result[cursor:])
                result = "".join(pieces)
        return result, counts

    # -- object level ---------------------------------------------------------

    def scan(self, payload: Any) -> ScanResult:
        """Walk a JSON-shaped payload, redacting or blocking per mode."""
        if self.mode == "off":
            return ScanResult(payload=payload, findings=(), blocked=False, mode=self.mode)

        counts: dict[str, int] = {}
        scrubbed = self._walk(payload, counts)

        by_name = {d.name: d for d in self.detectors}
        findings = tuple(
            Finding(
                detector=name,
                category=by_name[name].category,
                severity=by_name[name].severity,
                count=count,
            )
            for name, count in sorted(counts.items())
        )

        blocked = self.mode == "block" and any(
            f.severity == SEVERITY_HIGH for f in findings
        )
        return ScanResult(
            payload=None if blocked else scrubbed,
            findings=findings,
            blocked=blocked,
            mode=self.mode,
        )

    def _walk(self, value: Any, counts: dict[str, int]) -> Any:
        if isinstance(value, str):
            text, found = self.scan_text(value)
            for name, count in found.items():
                counts[name] = counts.get(name, 0) + count
            return text
        if isinstance(value, dict):
            return {key: self._walk(item, counts) for key, item in value.items()}
        if isinstance(value, list):
            return [self._walk(item, counts) for item in value]
        return value
