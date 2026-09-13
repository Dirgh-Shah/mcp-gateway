"""API key authentication.

Keys look like ``mcpg_<key_id>_<secret>``. The key id is a public lookup
handle; the secret is never stored, only ``sha256(secret)``.

Authentication is written so that an unknown key id, a disabled key and a wrong
secret all walk the same code path: a hash is always computed and always
compared with :func:`hmac.compare_digest`, against a fixed decoy digest when no
record exists. That keeps the work done roughly constant, so response time does
not leak whether a key id is real.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from app.config import KEY_ID_LENGTH, KEY_PREFIX, KEY_SECRET_BYTES

KEY_PATTERN = re.compile(
    rf"^{KEY_PREFIX}_([0-9a-f]{{{KEY_ID_LENGTH}}})_([A-Za-z0-9_\-]{{16,}})$"
)

#: Compared against when no record matches, so the miss path costs the same as
#: the wrong-secret path. Its preimage is irrelevant; it must never match.
_DECOY_DIGEST = hashlib.sha256(b"mcpg-decoy-never-a-valid-secret").hexdigest()


class AuthError(Exception):
    """Raised when a presented key cannot be resolved to a principal."""


@dataclass(frozen=True)
class Principal:
    """The authenticated caller."""

    name: str
    role: str
    key_id: str


@dataclass(frozen=True)
class KeyRecord:
    """What is safe to persist about a key."""

    key_id: str
    principal: str
    role: str
    secret_sha256: str
    created_at: str
    disabled: bool = False


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_key(principal: str, role: str) -> tuple[str, KeyRecord]:
    """Mint a key. Returns (plaintext_key, record_to_store).

    The plaintext is returned exactly once, here. It is not recoverable from
    the record.
    """
    if not principal or not role:
        raise ValueError("principal and role are both required")
    key_id = secrets.token_hex(KEY_ID_LENGTH // 2)
    secret = secrets.token_urlsafe(KEY_SECRET_BYTES)
    record = KeyRecord(
        key_id=key_id,
        principal=principal,
        role=role,
        secret_sha256=hash_secret(secret),
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    return f"{KEY_PREFIX}_{key_id}_{secret}", record


def _split(presented: str) -> tuple[str, str]:
    """Split a presented key into (key_id, secret) without raising.

    A malformed key yields a key id that cannot match any record, which sends
    it down the same decoy-compare path as an unknown key id.
    """
    match = KEY_PATTERN.match(presented.strip())
    if match is None:
        return "", presented
    return match.group(1), match.group(2)


class KeyStore:
    """An in-memory set of key records, loaded from JSON on disk."""

    def __init__(self, records: Iterable[KeyRecord]):
        self._by_id: dict[str, KeyRecord] = {}
        for record in records:
            if record.key_id in self._by_id:
                raise ValueError(f"duplicate key id in key store: {record.key_id}")
            self._by_id[record.key_id] = record

    def __len__(self) -> int:
        return len(self._by_id)

    @classmethod
    def load(cls, path: str | Path) -> "KeyStore":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(
                f"key store {path} does not exist. Mint a key with "
                f"`python scripts/keygen.py`."
            )
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(f"key store {path} must contain a JSON list")
        records = []
        for item in raw:
            try:
                records.append(
                    KeyRecord(
                        key_id=item["key_id"],
                        principal=item["principal"],
                        role=item["role"],
                        secret_sha256=item["secret_sha256"],
                        created_at=item["created_at"],
                        disabled=bool(item.get("disabled", False)),
                    )
                )
            except KeyError as exc:
                raise ValueError(f"key store {path}: record missing field {exc}") from exc
        return cls(records)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        payload = [asdict(record) for record in self._by_id.values()]
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def records(self) -> list[KeyRecord]:
        """All stored records, oldest first."""
        return sorted(self._by_id.values(), key=lambda record: record.created_at)

    def add(self, record: KeyRecord) -> None:
        if record.key_id in self._by_id:
            raise ValueError(f"duplicate key id in key store: {record.key_id}")
        self._by_id[record.key_id] = record

    def authenticate(self, presented: str) -> Principal:
        """Resolve a presented key to a Principal, or raise AuthError.

        The error message is deliberately identical for every failure mode.
        """
        key_id, secret = _split(presented or "")
        record = self._by_id.get(key_id)
        expected = record.secret_sha256 if record is not None else _DECOY_DIGEST

        digest = hash_secret(secret)
        matched = hmac.compare_digest(digest, expected)

        if record is None or not matched or record.disabled:
            raise AuthError("invalid API key")
        return Principal(name=record.principal, role=record.role, key_id=record.key_id)
