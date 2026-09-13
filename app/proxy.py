"""Upstream routing and JSON-RPC forwarding.

Routing and error mapping are pure logic and are tested against a fake client.
The only part that touches the network is :class:`HttpxUpstreamClient`, which
imports httpx lazily so that the routing logic can be imported and tested in an
environment where httpx is not installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

import yaml

from app.config import DEFAULT_UPSTREAM_TIMEOUT_SECONDS

# --- JSON-RPC error codes (single source of truth) ---------------------------
# -32768..-32000 is reserved by the spec for pre-defined errors; the
# implementation-defined server range is -32099..-32000.

ERROR_PARSE = -32700
ERROR_INVALID_REQUEST = -32600
ERROR_METHOD_NOT_FOUND = -32601
ERROR_INVALID_PARAMS = -32602
ERROR_INTERNAL = -32603

ERROR_UNAUTHENTICATED = -32001
ERROR_FORBIDDEN = -32002
ERROR_RATE_LIMITED = -32003
ERROR_UPSTREAM_TIMEOUT = -32004
ERROR_UPSTREAM_UNAVAILABLE = -32005
ERROR_UPSTREAM_MALFORMED = -32006
ERROR_NO_ROUTE = -32007
ERROR_RESPONSE_BLOCKED = -32008


class UpstreamError(Exception):
    """An upstream failure already mapped to a JSON-RPC error code."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

    def to_jsonrpc_error(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True)
class Upstream:
    name: str
    url: str
    tools: tuple[str, ...]

    def serves(self, tool: str) -> bool:
        return any(fnmatchcase(tool, pattern) for pattern in self.tools)


class UpstreamClient(Protocol):
    """Anything that can POST a JSON-RPC payload and return the parsed reply."""

    async def post(self, url: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        ...


def load_upstreams(path: str | Path) -> tuple[Upstream, ...]:
    """Read the `upstreams:` section of the policy file."""
    path = Path(path)
    if not path.exists():
        raise UpstreamError(ERROR_INTERNAL, f"policy file {path} does not exist")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = raw.get("upstreams")
    if not isinstance(entries, list) or not entries:
        raise UpstreamError(
            ERROR_INTERNAL, f"{path} must define a non-empty `upstreams` list"
        )
    upstreams = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise UpstreamError(ERROR_INTERNAL, "each upstream must be a mapping")
        missing = {"name", "url", "tools"} - set(entry)
        if missing:
            raise UpstreamError(
                ERROR_INTERNAL,
                f"upstream missing field(s): {', '.join(sorted(missing))}",
            )
        name = str(entry["name"])
        if name in seen:
            raise UpstreamError(ERROR_INTERNAL, f"duplicate upstream name {name!r}")
        seen.add(name)
        tools = entry["tools"]
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            raise UpstreamError(
                ERROR_INTERNAL, f"upstream {name!r}: tools must be a list of strings"
            )
        upstreams.append(
            Upstream(name=name, url=str(entry["url"]), tools=tuple(tools))
        )
    return tuple(upstreams)


class Proxy:
    def __init__(self, upstreams: Sequence[Upstream], client: UpstreamClient):
        if not upstreams:
            raise UpstreamError(ERROR_INTERNAL, "at least one upstream is required")
        self.upstreams = tuple(upstreams)
        self.client = client

    def route(self, tool: str) -> Upstream:
        """First upstream whose patterns match. Order in the file is priority."""
        for upstream in self.upstreams:
            if upstream.serves(tool):
                return upstream
        raise UpstreamError(ERROR_NO_ROUTE, f"no upstream serves tool {tool!r}")

    async def list_tools(self, request_id: Any = 1) -> list[dict[str, Any]]:
        """Fan out tools/list to every upstream and merge the catalogues.

        A name collision between upstreams is an error, not a silent overwrite:
        it would make routing ambiguous.
        """
        merged: dict[str, dict[str, Any]] = {}
        for upstream in self.upstreams:
            reply = await self._post(
                upstream, {"jsonrpc": "2.0", "id": request_id, "method": "tools/list"}
            )
            tools = (reply.get("result") or {}).get("tools")
            if not isinstance(tools, list):
                raise UpstreamError(
                    ERROR_UPSTREAM_MALFORMED,
                    f"upstream {upstream.name!r} returned no tools list",
                )
            for tool in tools:
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                    raise UpstreamError(
                        ERROR_UPSTREAM_MALFORMED,
                        f"upstream {upstream.name!r} returned a malformed tool entry",
                    )
                name = tool["name"]
                if name in merged:
                    raise UpstreamError(
                        ERROR_UPSTREAM_MALFORMED,
                        f"tool {name!r} is advertised by more than one upstream",
                    )
                merged[name] = tool
        return list(merged.values())

    async def call_tool(
        self, tool: str, arguments: Mapping[str, Any], request_id: Any = 1
    ) -> tuple[Upstream, dict[str, Any]]:
        upstream = self.route(tool)
        reply = await self._post(
            upstream,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": tool, "arguments": dict(arguments)},
            },
        )
        return upstream, reply

    async def _post(
        self, upstream: Upstream, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        reply = await self.client.post(upstream.url, payload)
        if not isinstance(reply, dict):
            raise UpstreamError(
                ERROR_UPSTREAM_MALFORMED,
                f"upstream {upstream.name!r} returned a non-object response",
            )
        if "error" not in reply and "result" not in reply:
            raise UpstreamError(
                ERROR_UPSTREAM_MALFORMED,
                f"upstream {upstream.name!r} returned neither result nor error",
            )
        return reply


class HttpxUpstreamClient:
    """The real client. httpx is imported on construction, not at module import."""

    def __init__(self, timeout: float = DEFAULT_UPSTREAM_TIMEOUT_SECONDS):
        import httpx  # noqa: PLC0415 - deliberate lazy import

        self._httpx = httpx
        self._client = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def post(self, url: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        httpx = self._httpx
        try:
            response = await self._client.post(url, json=dict(payload))
        except httpx.TimeoutException as exc:
            raise UpstreamError(
                ERROR_UPSTREAM_TIMEOUT, f"upstream timed out: {exc}"
            ) from exc
        except httpx.RequestError as exc:
            raise UpstreamError(
                ERROR_UPSTREAM_UNAVAILABLE, f"upstream unreachable: {exc}"
            ) from exc

        if response.status_code >= 500:
            raise UpstreamError(
                ERROR_UPSTREAM_UNAVAILABLE,
                f"upstream returned HTTP {response.status_code}",
            )
        if response.status_code >= 400:
            raise UpstreamError(
                ERROR_UPSTREAM_MALFORMED,
                f"upstream rejected the request with HTTP {response.status_code}",
            )
        try:
            return response.json()
        except ValueError as exc:
            raise UpstreamError(
                ERROR_UPSTREAM_MALFORMED, "upstream returned invalid JSON"
            ) from exc
