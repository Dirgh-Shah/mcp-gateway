"""Mint API keys into the key store.

    python scripts/keygen.py issue --principal alice --role reader
    python scripts/keygen.py list

The plaintext key is printed once and never stored. If it is lost, issue a new
one and disable the old record.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.auth import KeyStore, generate_key  # noqa: E402
from app.policy import Policy, PolicyError  # noqa: E402


def _load_or_empty(path: Path) -> KeyStore:
    if path.exists():
        return KeyStore.load(path)
    return KeyStore([])


def cmd_issue(args: argparse.Namespace) -> int:
    keys_path = Path(args.keys_file)
    policy_path = Path(args.policy_file)

    if policy_path.exists():
        try:
            policy = Policy.load(policy_path)
        except PolicyError as exc:
            print(f"error: {policy_path} is not a valid policy: {exc}", file=sys.stderr)
            return 2
        if args.role not in policy.roles:
            known = ", ".join(sorted(policy.roles))
            print(
                f"error: role {args.role!r} is not defined in {policy_path}. "
                f"Known roles: {known}",
                file=sys.stderr,
            )
            return 2
    else:
        print(
            f"warning: {policy_path} not found, cannot validate the role",
            file=sys.stderr,
        )

    store = _load_or_empty(keys_path)
    plaintext, record = generate_key(args.principal, args.role)
    store.add(record)
    store.save(keys_path)

    print(f"principal : {record.principal}")
    print(f"role      : {record.role}")
    print(f"key id    : {record.key_id}")
    print(f"stored in : {keys_path}")
    print()
    print("API key (shown once, not recoverable):")
    print(f"  {plaintext}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    keys_path = Path(args.keys_file)
    if not keys_path.exists():
        print(f"no key store at {keys_path}", file=sys.stderr)
        return 1
    store = KeyStore.load(keys_path)
    print(f"{'key id':<14}{'principal':<20}{'role':<14}{'state':<10}created")
    for record in store.records():
        state = "disabled" if record.disabled else "active"
        print(
            f"{record.key_id:<14}{record.principal:<20}{record.role:<14}"
            f"{state:<10}{record.created_at}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MCP Gateway key management")
    parser.add_argument("--keys-file", default="keys.json")
    parser.add_argument("--policy-file", default="policy.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    issue = sub.add_parser("issue", help="mint a new API key")
    issue.add_argument("--principal", required=True)
    issue.add_argument("--role", required=True)
    issue.set_defaults(func=cmd_issue)

    listing = sub.add_parser("list", help="list stored key records")
    listing.set_defaults(func=cmd_list)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
