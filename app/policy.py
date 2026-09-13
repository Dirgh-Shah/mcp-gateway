"""Authorization policy.

Deny by default. A role must exist and must explicitly allow a tool pattern for
a call to proceed; a matching deny pattern overrides any allow. Arguments are
bounded before anything is forwarded upstream.

The policy file is validated strictly at load time. An unrecognised key is an
error rather than something silently ignored, because a typo in a deny rule
that is quietly dropped is a security hole that looks like a working config.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

# --- decision codes ----------------------------------------------------------

ALLOW = "allow"
UNKNOWN_ROLE = "unknown_role"
NOT_ALLOWED = "not_allowed"
DENIED_BY_RULE = "denied_by_rule"
ARGUMENT_TOO_LONG = "argument_too_long"
COLLECTION_TOO_LARGE = "collection_too_large"
VALUE_NOT_PERMITTED = "value_not_permitted"

#: Top-level keys the policy file may contain. `upstreams` is consumed by
#: app.proxy, not here, but is listed so strict validation does not reject it.
_TOP_LEVEL_KEYS = {"version", "roles", "upstreams"}
_ROLE_KEYS = {"allow", "deny", "admin", "limits", "arguments"}
_LIMIT_KEYS = {"max_string_length", "max_collection_size"}
_ARG_KEYS = {"max_length", "max_items", "enum"}

SUPPORTED_POLICY_VERSION = 1


class PolicyError(RuntimeError):
    """Raised when a policy file is malformed."""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str
    reason: str

    def __bool__(self) -> bool:  # pragma: no cover - convenience only
        return self.allowed


@dataclass(frozen=True)
class ArgumentConstraint:
    max_length: int | None = None
    max_items: int | None = None
    enum: tuple[Any, ...] | None = None


@dataclass(frozen=True)
class Role:
    name: str
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    admin: bool = False
    max_string_length: int | None = None
    max_collection_size: int | None = None
    arguments: Mapping[str, Mapping[str, ArgumentConstraint]] = field(
        default_factory=dict
    )


def _as_patterns(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where} must be a list of strings")
    return tuple(value)


def _positive_int(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PolicyError(f"{where} must be a positive integer, got {value!r}")
    return value


def _parse_role(name: str, raw: Any) -> Role:
    if not isinstance(raw, dict):
        raise PolicyError(f"role {name!r} must be a mapping")
    unknown = set(raw) - _ROLE_KEYS
    if unknown:
        raise PolicyError(
            f"role {name!r} has unknown key(s): {', '.join(sorted(unknown))}"
        )

    limits = raw.get("limits") or {}
    if not isinstance(limits, dict):
        raise PolicyError(f"role {name!r}: limits must be a mapping")
    unknown = set(limits) - _LIMIT_KEYS
    if unknown:
        raise PolicyError(
            f"role {name!r}: unknown limit(s): {', '.join(sorted(unknown))}"
        )

    arguments: dict[str, dict[str, ArgumentConstraint]] = {}
    raw_arguments = raw.get("arguments") or {}
    if not isinstance(raw_arguments, dict):
        raise PolicyError(f"role {name!r}: arguments must be a mapping")
    for tool_pattern, args in raw_arguments.items():
        if not isinstance(args, dict):
            raise PolicyError(
                f"role {name!r}: arguments.{tool_pattern} must be a mapping"
            )
        parsed: dict[str, ArgumentConstraint] = {}
        for arg_name, constraint in args.items():
            if not isinstance(constraint, dict):
                raise PolicyError(
                    f"role {name!r}: arguments.{tool_pattern}.{arg_name} "
                    f"must be a mapping"
                )
            unknown = set(constraint) - _ARG_KEYS
            if unknown:
                raise PolicyError(
                    f"role {name!r}: arguments.{tool_pattern}.{arg_name} has "
                    f"unknown key(s): {', '.join(sorted(unknown))}"
                )
            enum = constraint.get("enum")
            if enum is not None and (not isinstance(enum, list) or not enum):
                raise PolicyError(
                    f"role {name!r}: arguments.{tool_pattern}.{arg_name}.enum "
                    f"must be a non-empty list"
                )
            parsed[arg_name] = ArgumentConstraint(
                max_length=(
                    _positive_int(
                        constraint["max_length"],
                        f"role {name!r}: arguments.{tool_pattern}.{arg_name}.max_length",
                    )
                    if "max_length" in constraint
                    else None
                ),
                max_items=(
                    _positive_int(
                        constraint["max_items"],
                        f"role {name!r}: arguments.{tool_pattern}.{arg_name}.max_items",
                    )
                    if "max_items" in constraint
                    else None
                ),
                enum=tuple(enum) if enum is not None else None,
            )
        arguments[tool_pattern] = parsed

    return Role(
        name=name,
        allow=_as_patterns(raw.get("allow"), f"role {name!r}: allow"),
        deny=_as_patterns(raw.get("deny"), f"role {name!r}: deny"),
        admin=bool(raw.get("admin", False)),
        max_string_length=(
            _positive_int(
                limits["max_string_length"], f"role {name!r}: max_string_length"
            )
            if "max_string_length" in limits
            else None
        ),
        max_collection_size=(
            _positive_int(
                limits["max_collection_size"], f"role {name!r}: max_collection_size"
            )
            if "max_collection_size" in limits
            else None
        ),
        arguments=arguments,
    )


class Policy:
    """Compiled policy. Construct via :meth:`load` or :meth:`from_dict`."""

    def __init__(self, roles: Mapping[str, Role]):
        self._roles = dict(roles)

    @property
    def roles(self) -> Mapping[str, Role]:
        return dict(self._roles)

    @classmethod
    def from_dict(cls, raw: Any) -> "Policy":
        if not isinstance(raw, dict):
            raise PolicyError("policy must be a mapping")
        unknown = set(raw) - _TOP_LEVEL_KEYS
        if unknown:
            raise PolicyError(
                f"policy has unknown top-level key(s): {', '.join(sorted(unknown))}"
            )
        version = raw.get("version")
        if version != SUPPORTED_POLICY_VERSION:
            raise PolicyError(
                f"policy version must be {SUPPORTED_POLICY_VERSION}, got {version!r}"
            )
        roles_raw = raw.get("roles")
        if not isinstance(roles_raw, dict) or not roles_raw:
            raise PolicyError("policy must define at least one role under `roles`")
        return cls({name: _parse_role(name, body) for name, body in roles_raw.items()})

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        path = Path(path)
        if not path.exists():
            raise PolicyError(f"policy file {path} does not exist")
        return cls.from_dict(yaml.safe_load(path.read_text(encoding="utf-8")))

    # -- queries --------------------------------------------------------------

    def is_admin(self, role: str) -> bool:
        rules = self._roles.get(role)
        return bool(rules and rules.admin)

    def _match(self, rules: Role, tool: str) -> Decision | None:
        """Name-level matching only. Returns None when the tool is allowed."""
        for pattern in rules.deny:
            if fnmatchcase(tool, pattern):
                return Decision(
                    False,
                    DENIED_BY_RULE,
                    f"tool {tool!r} matches deny pattern {pattern!r} for role "
                    f"{rules.name!r}",
                )
        for pattern in rules.allow:
            if fnmatchcase(tool, pattern):
                return None
        return Decision(
            False,
            NOT_ALLOWED,
            f"role {rules.name!r} has no allow pattern matching tool {tool!r}",
        )

    def decide(self, role: str, tool: str, arguments: Any = None) -> Decision:
        """May this role call this tool with these arguments?"""
        rules = self._roles.get(role)
        if rules is None:
            return Decision(
                False, UNKNOWN_ROLE, f"role {role!r} is not defined in the policy"
            )

        name_decision = self._match(rules, tool)
        if name_decision is not None:
            return name_decision

        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return Decision(
                False, VALUE_NOT_PERMITTED, "tool arguments must be a JSON object"
            )

        bounds = self._check_bounds(rules, arguments, path="arguments")
        if bounds is not None:
            return bounds

        specific = self._check_named_arguments(rules, tool, arguments)
        if specific is not None:
            return specific

        return Decision(True, ALLOW, f"role {rules.name!r} may call {tool!r}")

    def _check_bounds(self, rules: Role, value: Any, path: str) -> Decision | None:
        """Role-wide string and collection limits, applied at every depth."""
        if isinstance(value, str):
            if (
                rules.max_string_length is not None
                and len(value) > rules.max_string_length
            ):
                return Decision(
                    False,
                    ARGUMENT_TOO_LONG,
                    f"{path} is {len(value)} characters, over the "
                    f"{rules.max_string_length} character limit for role "
                    f"{rules.name!r}",
                )
            return None
        if isinstance(value, dict):
            if (
                rules.max_collection_size is not None
                and len(value) > rules.max_collection_size
            ):
                return Decision(
                    False,
                    COLLECTION_TOO_LARGE,
                    f"{path} has {len(value)} entries, over the "
                    f"{rules.max_collection_size} entry limit for role "
                    f"{rules.name!r}",
                )
            for key, item in value.items():
                found = self._check_bounds(rules, item, f"{path}.{key}")
                if found is not None:
                    return found
            return None
        if isinstance(value, (list, tuple)):
            if (
                rules.max_collection_size is not None
                and len(value) > rules.max_collection_size
            ):
                return Decision(
                    False,
                    COLLECTION_TOO_LARGE,
                    f"{path} has {len(value)} items, over the "
                    f"{rules.max_collection_size} item limit for role "
                    f"{rules.name!r}",
                )
            for index, item in enumerate(value):
                found = self._check_bounds(rules, item, f"{path}[{index}]")
                if found is not None:
                    return found
        return None

    def _check_named_arguments(
        self, rules: Role, tool: str, arguments: Mapping[str, Any]
    ) -> Decision | None:
        for tool_pattern, constraints in rules.arguments.items():
            if not fnmatchcase(tool, tool_pattern):
                continue
            for arg_name, constraint in constraints.items():
                if arg_name not in arguments:
                    continue
                value = arguments[arg_name]
                if (
                    constraint.max_length is not None
                    and isinstance(value, str)
                    and len(value) > constraint.max_length
                ):
                    return Decision(
                        False,
                        ARGUMENT_TOO_LONG,
                        f"argument {arg_name!r} of {tool!r} is {len(value)} "
                        f"characters, over its {constraint.max_length} character limit",
                    )
                if (
                    constraint.max_items is not None
                    and isinstance(value, (list, tuple, dict))
                    and len(value) > constraint.max_items
                ):
                    return Decision(
                        False,
                        COLLECTION_TOO_LARGE,
                        f"argument {arg_name!r} of {tool!r} has {len(value)} "
                        f"items, over its {constraint.max_items} item limit",
                    )
                if constraint.enum is not None and value not in constraint.enum:
                    return Decision(
                        False,
                        VALUE_NOT_PERMITTED,
                        f"argument {arg_name!r} of {tool!r} is not one of the "
                        f"permitted values",
                    )
        return None

    def visible_tools(
        self, role: str, tools: Sequence[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]:
        """Filter a tools/list response to what this role may actually call.

        An unknown role sees nothing. A tool this role cannot call is never
        advertised, so the model is not tempted to try it.
        """
        rules = self._roles.get(role)
        if rules is None:
            return []
        visible = []
        for tool in tools:
            name = tool.get("name")
            if not isinstance(name, str):
                raise PolicyError(f"tool entry has no string name: {tool!r}")
            if self._match(rules, name) is None:
                visible.append(tool)
        return visible


def role_names(policy: Policy) -> Iterable[str]:  # pragma: no cover - helper
    return policy.roles.keys()
