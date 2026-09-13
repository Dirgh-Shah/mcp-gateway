import asyncio

import pytest

from app.proxy import (
    ERROR_NO_ROUTE,
    ERROR_UPSTREAM_MALFORMED,
    ERROR_UPSTREAM_TIMEOUT,
    Proxy,
    Upstream,
    UpstreamError,
    load_upstreams,
)


class FakeClient:
    """Records calls and replays scripted replies, per URL."""

    def __init__(self, replies=None, raises=None):
        self.replies = replies or {}
        self.raises = raises
        self.calls = []

    async def post(self, url, payload):
        self.calls.append((url, dict(payload)))
        if self.raises is not None:
            raise self.raises
        reply = self.replies.get(url)
        if reply is None:
            raise AssertionError(f"no scripted reply for {url}")
        return reply


DOCS = Upstream(name="docs", url="http://docs/mcp", tools=("get_*", "search_*"))
OPS = Upstream(name="ops", url="http://ops/mcp", tools=("*",))


def run(coro):
    return asyncio.run(coro)


def test_routes_to_the_first_matching_upstream():
    proxy = Proxy([DOCS, OPS], FakeClient())
    assert proxy.route("get_document").name == "docs"
    assert proxy.route("restart_service").name == "ops"


def test_unroutable_tool_raises_no_route():
    proxy = Proxy([DOCS], FakeClient())
    with pytest.raises(UpstreamError) as excinfo:
        proxy.route("restart_service")
    assert excinfo.value.code == ERROR_NO_ROUTE


def test_call_tool_forwards_a_well_formed_jsonrpc_request():
    client = FakeClient({DOCS.url: {"jsonrpc": "2.0", "id": 7, "result": {"ok": True}}})
    proxy = Proxy([DOCS], client)
    upstream, reply = run(proxy.call_tool("get_document", {"id": "doc-1"}, request_id=7))

    url, payload = client.calls[0]
    assert url == DOCS.url
    assert payload["method"] == "tools/call"
    assert payload["params"] == {"name": "get_document", "arguments": {"id": "doc-1"}}
    assert payload["jsonrpc"] == "2.0"
    assert upstream.name == "docs"
    assert reply["result"] == {"ok": True}


def test_upstream_errors_are_passed_through_not_swallowed():
    error = {"code": -32601, "message": "unknown tool"}
    client = FakeClient({DOCS.url: {"jsonrpc": "2.0", "id": 1, "error": error}})
    _, reply = run(Proxy([DOCS], client).call_tool("get_document", {}))
    assert reply["error"] == error


def test_a_client_failure_keeps_its_mapped_code():
    client = FakeClient(raises=UpstreamError(ERROR_UPSTREAM_TIMEOUT, "upstream timed out"))
    with pytest.raises(UpstreamError) as excinfo:
        run(Proxy([DOCS], client).call_tool("get_document", {}))
    assert excinfo.value.code == ERROR_UPSTREAM_TIMEOUT


def test_a_reply_that_is_neither_result_nor_error_is_malformed():
    client = FakeClient({DOCS.url: {"jsonrpc": "2.0", "id": 1}})
    with pytest.raises(UpstreamError) as excinfo:
        run(Proxy([DOCS], client).call_tool("get_document", {}))
    assert excinfo.value.code == ERROR_UPSTREAM_MALFORMED


def test_a_non_object_reply_is_malformed():
    client = FakeClient({DOCS.url: ["not", "an", "object"]})
    with pytest.raises(UpstreamError) as excinfo:
        run(Proxy([DOCS], client).call_tool("get_document", {}))
    assert excinfo.value.code == ERROR_UPSTREAM_MALFORMED


def test_list_tools_merges_catalogues_across_upstreams():
    client = FakeClient(
        {
            DOCS.url: {"id": 1, "result": {"tools": [{"name": "get_document"}]}},
            OPS.url: {"id": 1, "result": {"tools": [{"name": "restart_service"}]}},
        }
    )
    tools = run(Proxy([DOCS, OPS], client).list_tools())
    assert {tool["name"] for tool in tools} == {"get_document", "restart_service"}


def test_a_tool_name_served_by_two_upstreams_is_an_error():
    client = FakeClient(
        {
            DOCS.url: {"id": 1, "result": {"tools": [{"name": "get_document"}]}},
            OPS.url: {"id": 1, "result": {"tools": [{"name": "get_document"}]}},
        }
    )
    with pytest.raises(UpstreamError) as excinfo:
        run(Proxy([DOCS, OPS], client).list_tools())
    assert excinfo.value.code == ERROR_UPSTREAM_MALFORMED


def test_list_tools_rejects_a_malformed_catalogue():
    client = FakeClient({DOCS.url: {"id": 1, "result": {"tools": [{"nome": "typo"}]}}})
    with pytest.raises(UpstreamError):
        run(Proxy([DOCS], client).list_tools())


def test_a_proxy_needs_at_least_one_upstream():
    with pytest.raises(UpstreamError):
        Proxy([], FakeClient())


def test_shipped_policy_file_defines_a_usable_upstream():
    upstreams = load_upstreams("policy.yaml")
    assert upstreams[0].name == "demo"
    assert upstreams[0].serves("get_document")
