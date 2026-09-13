"""Tamper-evident audit log.

Every decision the gateway makes becomes one row. Each row carries the hash of
the row before it:

    hash = sha256(prev_hash + canonical_json(entry))

so changing any field of any row invalidates that row's hash and every hash
after it. :meth:`AuditLog.verify` walks the chain and names the first row that
does not reconcile.

The genesis hash is derived from the deployment signing secret rather than being
a constant. An attacker with write access to the database can still recompute a
whole consistent chain, but only if they also hold the secret. This is
tamper-evident, not tamper-proof; see docs/AUDIT_DESIGN.md.

What is never written here: tool arguments and tool results. They are exactly
the fields most likely to contain the secrets this system exists to protect.
Findings are recorded as counts by detector, not as matched text.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

GENESIS_LABEL = b"mcpg-audit-genesis-v1"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    request_id    TEXT    NOT NULL,
    principal     TEXT    NOT NULL,
    role          TEXT    NOT NULL,
    tool          TEXT    NOT NULL,
    decision      TEXT    NOT NULL,
    decision_code TEXT    NOT NULL,
    upstream      TEXT,
    latency_ms    REAL,
    findings      TEXT    NOT NULL,
    prev_hash     TEXT    NOT NULL,
    hash          TEXT    NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
"""

_FIELDS = (
    "seq",
    "ts",
    "request_id",
    "principal",
    "role",
    "tool",
    "decision",
    "decision_code",
    "upstream",
    "latency_ms",
    "findings",
)


class AuditError(RuntimeError):
    """Raised when the log cannot be written or read."""


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    rows_checked: int
    first_bad_seq: int | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "rows_checked": self.rows_checked,
            "first_bad_seq": self.first_bad_seq,
            "reason": self.reason,
        }


def canonical_json(entry: dict[str, Any]) -> str:
    """A byte-stable rendering of an entry. Key order must never vary."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def genesis_hash(signing_secret: str) -> str:
    return hmac.new(
        signing_secret.encode("utf-8"), GENESIS_LABEL, hashlib.sha256
    ).hexdigest()


def chain_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    payload = prev_hash + canonical_json(entry)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, signing_secret: str):
        if not signing_secret:
            raise AuditError("audit log requires a signing secret")
        self.path = str(path)
        self._signing_secret = signing_secret
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.executescript(_SCHEMA)
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "AuditLog":  # pragma: no cover - convenience
        return self

    def __exit__(self, *_exc: object) -> None:  # pragma: no cover - convenience
        self.close()

    # -- writing --------------------------------------------------------------

    def _head(self) -> tuple[int, str]:
        row = self._connection.execute(
            "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return 0, genesis_hash(self._signing_secret)
        return int(row["seq"]), str(row["hash"])

    def append(
        self,
        *,
        request_id: str,
        principal: str,
        role: str,
        tool: str,
        decision: str,
        decision_code: str,
        upstream: str | None = None,
        latency_ms: float | None = None,
        findings: Sequence[dict[str, Any]] = (),
        ts: str | None = None,
    ) -> dict[str, Any]:
        """Append one entry and return it, including its hash."""
        last_seq, prev_hash = self._head()
        entry = {
            "seq": last_seq + 1,
            "ts": ts or datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "request_id": request_id,
            "principal": principal,
            "role": role,
            "tool": tool,
            "decision": decision,
            "decision_code": decision_code,
            "upstream": upstream,
            "latency_ms": latency_ms,
            "findings": canonical_json_list(findings),
        }
        digest = chain_hash(prev_hash, entry)
        self._connection.execute(
            "INSERT INTO audit_log "
            "(seq, ts, request_id, principal, role, tool, decision, decision_code,"
            " upstream, latency_ms, findings, prev_hash, hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                entry["seq"],
                entry["ts"],
                entry["request_id"],
                entry["principal"],
                entry["role"],
                entry["tool"],
                entry["decision"],
                entry["decision_code"],
                entry["upstream"],
                entry["latency_ms"],
                entry["findings"],
                prev_hash,
                digest,
            ),
        )
        self._connection.commit()
        return {**entry, "prev_hash": prev_hash, "hash": digest}

    # -- reading --------------------------------------------------------------

    def rows(self) -> list[sqlite3.Row]:
        return list(
            self._connection.execute("SELECT * FROM audit_log ORDER BY seq ASC")
        )

    def count(self) -> int:
        return int(
            self._connection.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()[
                "n"
            ]
        )

    def verify(self) -> VerifyResult:
        """Walk the chain, reporting the first row that does not reconcile."""
        expected_prev = genesis_hash(self._signing_secret)
        checked = 0
        expected_seq = 1

        for row in self.rows():
            seq = int(row["seq"])
            if seq != expected_seq:
                return VerifyResult(
                    ok=False,
                    rows_checked=checked,
                    first_bad_seq=seq,
                    reason=f"sequence gap: expected seq {expected_seq}, found {seq}",
                )
            if row["prev_hash"] != expected_prev:
                return VerifyResult(
                    ok=False,
                    rows_checked=checked,
                    first_bad_seq=seq,
                    reason=(
                        "prev_hash does not match the previous row's hash "
                        "(a row was removed, reordered, or the chain was re-rooted)"
                    ),
                )
            entry = {field: row[field] for field in _FIELDS}
            recomputed = chain_hash(row["prev_hash"], entry)
            if not hmac.compare_digest(recomputed, str(row["hash"])):
                return VerifyResult(
                    ok=False,
                    rows_checked=checked,
                    first_bad_seq=seq,
                    reason="row contents do not match its stored hash",
                )
            expected_prev = str(row["hash"])
            expected_seq += 1
            checked += 1

        return VerifyResult(ok=True, rows_checked=checked)


def canonical_json_list(findings: Iterable[dict[str, Any]]) -> str:
    return json.dumps(
        list(findings), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
