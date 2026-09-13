"""End-to-end tests through the HTTP layer.

These need fastapi and httpx installed (`pip install -e ".[dev]"`). The
upstream is a fake client, so nothing here touches the network.
"""

import tempfile
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from app.auth import KeyStore, generate_key  # noqa: E402
from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.proxy import (  # noqa: E402
    ERROR_FORBIDDEN,
    ERROR_RATE_LIMITED,
    ERROR_RESPONSE_BLOCKED,
    ERROR_UNAUTHENTICATED,
    ERROR_UPSTREAM_TIMEOUT,
    UpstreamError,
)

SIGNING_SECRET = "s" * 40
UPSTREAM_URL = "http://fake-upstream/mcp"

CATALOGUE = [
    {"name": "search_documents"},
    {"name": "get_document"},
    {"name": "delete_document"},
    {"name": "fetch_ci_config"},
]

POLICY = f"""
version: 1
upstreams:
  - name: demo
    url: {UPSTREAM_URL}
    tools: ["*"]
roles:
  reader:
    allow: ["search_*", "get_*"]
    deny: ["delete_*"]
    limits:
      max_string_length: 32
  operator:
    allow: ["*"]
    deny: []
  auditor:
    admin: true
    allow: []
    deny: ["*"]
"""


class FakeUpstream:
    def __init__(self, result=None, raises=None):
        self.result = result if result is not None else {
            "content": [{"type": "text", "text": "ok"}]
        }
        self.raises = raises
        self.calls = []

    async def post(self, url, payload):
        self.calls.append(dict(payload))
        if self.raises is not None:
            raise self.raises
        if payload["method"] == "tools/list":
            return {"jsonrpc": "2.0", "id": payload["id"], "result": {"tools": CATALOGUE}}
        return {"jsonrpc": "2.0", "id": payload["id"], "result": self.result}


class Harness:
    """Builds a gateway over a temp directory, with keys for each role."""

    def __init__(self, upstream, scanner_mode="redact", rpm=600, burst=100):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        (root / "policy.yaml").write_text(POLICY, encoding="utf-8")

        store = KeyStore([])
        self.keys = {}
        for principal, role in (
            ("alice", "reader"),
            ("olive", "operator"),
            ("aud", "auditor"),
        ):
            plaintext, record = generate_key(principal, role)
            store.add(record)
            self.keys[role] = plaintext
        store.save(root / "keys.json")

        settings = Settings(
            signing_secret=SIGNING_SECRET,
            policy_file=str(root / "policy.yaml"),
            keys_file=str(root / "keys.json"),
            audit_db=str(root / "audit.db"),
            scanner_mode=scanner_mode,
            rate_limit_rpm=rpm,
            rate_limit_burst=burst,
            upstream_timeout_seconds=5.0,
        )
        self.audit_db = root / "audit.db"
        self.app = create_app(settings, client=upstream)

    def __enter__(self):
        self.client = TestClient(self.app)
        self.client.__enter__()
        return self

    def __exit__(self, *exc):
        self.client.__exit__(*exc)
        self._tmp.cleanup()

    def rpc(self, role, method, params=None, rpc_id=1):
        headers = {} if role is None else {"Authorization": f"Bearer {self.keys[role]}"}
        body = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
        if params is not None:
            body["params"] = params
        return self.client.post("/mcp", json=body, headers=headers)


def test_healthz_is_open():
    with Harness(FakeUpstream()) as h:
        assert h.client.get("/healthz").json()["status"] == "ok"


def test_a_request_without_a_key_is_rejected():
    with Harness(FakeUpstream()) as h:
        response = h.rpc(None, "tools/list")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == ERROR_UNAUTHENTICATED


def test_a_forged_key_is_rejected():
    with Harness(FakeUpstream()) as h:
        response = h.client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer mcpg_000000000000_" + "a" * 43},
        )
        assert response.status_code == 401


def test_initialize_returns_server_info():
    with Harness(FakeUpstream()) as h:
        result = h.rpc("reader", "initialize").json()["result"]
        assert result["serverInfo"]["name"] == "mcp-gateway"
        assert "protocolVersion" in result


def test_tools_list_is_filtered_per_role():
    with Harness(FakeUpstream()) as h:
        reader = {t["name"] for t in h.rpc("reader", "tools/list").json()["result"]["tools"]}
        operator = {
            t["name"] for t in h.rpc("operator", "tools/list").json()["result"]["tools"]
        }
        assert reader == {"search_documents", "get_document"}
        assert operator == {t["name"] for t in CATALOGUE}


def test_an_allowed_call_reaches_the_upstream():
    upstream = FakeUpstream()
    with Harness(upstream) as h:
        response = h.rpc(
            "reader", "tools/call", {"name": "get_document", "arguments": {"id": "d1"}}
        )
        assert response.status_code == 200
        assert response.json()["result"]["content"][0]["text"] == "ok"
        assert upstream.calls[-1]["params"]["name"] == "get_document"


def test_a_denied_call_never_reaches_the_upstream():
    upstream = FakeUpstream()
    with Harness(upstream) as h:
        response = h.rpc(
            "reader", "tools/call", {"name": "delete_document", "arguments": {}}
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == ERROR_FORBIDDEN
        assert upstream.calls == []


def test_an_oversized_argument_never_reaches_the_upstream():
    upstream = FakeUpstream()
    with Harness(upstream) as h:
        response = h.rpc(
            "reader",
            "tools/call",
            {"name": "get_document", "arguments": {"id": "x" * 100}},
        )
        assert response.status_code == 403
        assert upstream.calls == []


def test_rate_limiting_returns_429_with_retry_after():
    with Harness(FakeUpstream(), rpm=60, burst=2) as h:
        for _ in range(2):
            assert h.rpc("reader", "tools/call", {"name": "get_document"}).status_code == 200
        limited = h.rpc("reader", "tools/call", {"name": "get_document"})
        assert limited.status_code == 429
        assert limited.json()["error"]["code"] == ERROR_RATE_LIMITED
        assert "Retry-After" in limited.headers


def test_a_secret_in_a_tool_result_is_redacted_before_the_client_sees_it():
    upstream = FakeUpstream(
        result={"content": [{"type": "text", "text": "key=AKIAIOSFODNN7EXAMPLE"}]}
    )
    with Harness(upstream) as h:
        body = h.rpc(
            "operator", "tools/call", {"name": "fetch_ci_config", "arguments": {}}
        ).json()
        text = body["result"]["content"][0]["text"]
        assert "AKIAIOSFODNN7EXAMPLE" not in text
        assert "[REDACTED:aws_access_key_id]" in text


def test_block_mode_withholds_the_whole_response():
    upstream = FakeUpstream(
        result={"content": [{"type": "text", "text": "key=AKIAIOSFODNN7EXAMPLE"}]}
    )
    with Harness(upstream, scanner_mode="block") as h:
        body = h.rpc(
            "operator", "tools/call", {"name": "fetch_ci_config", "arguments": {}}
        ).json()
        assert body["error"]["code"] == ERROR_RESPONSE_BLOCKED
        assert "AKIAIOSFODNN7EXAMPLE" not in str(body)


def test_an_upstream_timeout_maps_to_a_jsonrpc_error():
    upstream = FakeUpstream(raises=UpstreamError(ERROR_UPSTREAM_TIMEOUT, "timed out"))
    with Harness(upstream) as h:
        response = h.rpc("reader", "tools/call", {"name": "get_document"})
        assert response.status_code == 502
        assert response.json()["error"]["code"] == ERROR_UPSTREAM_TIMEOUT


def test_an_unsupported_method_is_reported_as_such():
    with Harness(FakeUpstream()) as h:
        assert h.rpc("reader", "resources/list").json()["error"]["code"] == -32601


def test_metrics_count_each_outcome():
    with Harness(FakeUpstream()) as h:
        h.rpc("reader", "tools/call", {"name": "get_document"})
        h.rpc("reader", "tools/call", {"name": "delete_document"})
        text = h.client.get("/metrics").text
        assert 'mcpg_requests_total{outcome="allowed"} 1' in text
        assert 'mcpg_requests_total{outcome="denied"} 1' in text
        assert "mcpg_upstream_latency_seconds_count 1" in text


def test_audit_verify_requires_an_admin_role():
    with Harness(FakeUpstream()) as h:
        assert h.client.get("/audit/verify").status_code == 401
        forbidden = h.client.get(
            "/audit/verify", headers={"Authorization": f"Bearer {h.keys['reader']}"}
        )
        assert forbidden.status_code == 403


def test_audit_verify_reports_a_clean_chain():
    with Harness(FakeUpstream()) as h:
        h.rpc("reader", "tools/call", {"name": "get_document"})
        h.rpc("reader", "tools/call", {"name": "delete_document"})
        body = h.client.get(
            "/audit/verify", headers={"Authorization": f"Bearer {h.keys['auditor']}"}
        ).json()
        assert body["ok"] is True
        assert body["rows_checked"] >= 2


def test_tampering_with_the_audit_database_is_reported():
    import sqlite3

    with Harness(FakeUpstream()) as h:
        h.rpc("reader", "tools/call", {"name": "get_document"})
        h.rpc("reader", "tools/call", {"name": "delete_document"})

        raw = sqlite3.connect(h.audit_db)
        raw.execute("DROP TRIGGER audit_log_no_update")
        raw.execute("UPDATE audit_log SET decision='allowed' WHERE seq=2")
        raw.commit()
        raw.close()

        response = h.client.get(
            "/audit/verify", headers={"Authorization": f"Bearer {h.keys['auditor']}"}
        )
        assert response.status_code == 409
        assert response.json()["ok"] is False
        assert response.json()["first_bad_seq"] == 2
