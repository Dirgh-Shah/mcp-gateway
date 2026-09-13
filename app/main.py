"""HTTP surface.

Four routes: the JSON-RPC endpoint, a health check, Prometheus metrics, and an
admin-only audit verification endpoint.

Order of operations for a tools/call, which is the whole point of the project:

    authenticate -> rate limit -> authorize (name, then arguments)
      -> forward upstream -> scan the response -> audit -> reply

Every one of those stages can end the request, and every ending is audited and
counted.
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app import metrics as metrics_module
from app.audit import AuditLog
from app.auth import AuthError, KeyStore, Principal
from app.config import Settings, load_settings
from app.metrics import MetricsRegistry
from app.policy import Policy
from app.proxy import (
    ERROR_FORBIDDEN,
    ERROR_INVALID_PARAMS,
    ERROR_INVALID_REQUEST,
    ERROR_METHOD_NOT_FOUND,
    ERROR_RATE_LIMITED,
    ERROR_RESPONSE_BLOCKED,
    ERROR_UNAUTHENTICATED,
    HttpxUpstreamClient,
    Proxy,
    UpstreamError,
    load_upstreams,
)
from app.ratelimit import RateLimiter
from app.scanner import Scanner

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "mcp-gateway"
SERVER_VERSION = "0.1.0"


def _jsonrpc_error(
    request_id: Any, code: int, message: str, status_code: int = 200, **extra: Any
) -> JSONResponse:
    body: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }
    headers = extra.pop("headers", None)
    return JSONResponse(body, status_code=status_code, headers=headers)


def _jsonrpc_result(request_id: Any, result: Any) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": result})


class Gateway:
    """Everything the request path needs, built once at startup."""

    def __init__(self, settings: Settings, client: Any | None = None):
        self.settings = settings
        self.policy = Policy.load(settings.policy_file)
        self.keys = KeyStore.load(settings.keys_file)
        self.audit = AuditLog(settings.audit_db, settings.signing_secret)
        self.scanner = Scanner(mode=settings.scanner_mode)
        self.limiter = RateLimiter(
            requests_per_minute=settings.rate_limit_rpm,
            burst=settings.rate_limit_burst,
        )
        self.metrics = MetricsRegistry()
        self.client = client or HttpxUpstreamClient(
            timeout=settings.upstream_timeout_seconds
        )
        self.proxy = Proxy(load_upstreams(settings.policy_file), self.client)

    async def aclose(self) -> None:
        close = getattr(self.client, "aclose", None)
        if close is not None:
            await close()
        self.audit.close()

    def authenticate(self, request: Request) -> Principal:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthError("invalid API key")
        return self.keys.authenticate(token)


def create_app(settings: Settings | None = None, client: Any | None = None) -> FastAPI:
    resolved = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.gateway = Gateway(resolved, client=client)
        try:
            yield
        finally:
            await app.state.gateway.aclose()

    app = FastAPI(title=SERVER_NAME, version=SERVER_VERSION, lifespan=lifespan)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": SERVER_VERSION}

    @app.get("/metrics", response_class=PlainTextResponse)
    async def prometheus_metrics(request: Request) -> PlainTextResponse:
        gateway: Gateway = request.app.state.gateway
        return PlainTextResponse(
            gateway.metrics.render(), media_type="text/plain; version=0.0.4"
        )

    @app.get("/audit/verify")
    async def audit_verify(request: Request) -> JSONResponse:
        gateway: Gateway = request.app.state.gateway
        try:
            principal = gateway.authenticate(request)
        except AuthError:
            gateway.metrics.increment_request(
                metrics_module.OUTCOME_UNAUTHENTICATED
            )
            return _jsonrpc_error(
                None, ERROR_UNAUTHENTICATED, "invalid API key", status_code=401
            )
        if not gateway.policy.is_admin(principal.role):
            gateway.metrics.increment_request(metrics_module.OUTCOME_DENIED)
            return _jsonrpc_error(
                None,
                ERROR_FORBIDDEN,
                "audit verification requires an admin role",
                status_code=403,
            )
        result = gateway.audit.verify()
        return JSONResponse(result.to_dict(), status_code=200 if result.ok else 409)

    @app.post("/mcp")
    async def mcp(request: Request) -> JSONResponse:
        gateway: Gateway = request.app.state.gateway
        request_id_header = request.headers.get("x-request-id")
        trace_id = request_id_header or str(uuid.uuid4())

        try:
            body = await request.json()
        except ValueError:
            return _jsonrpc_error(None, ERROR_INVALID_REQUEST, "body is not valid JSON")
        if not isinstance(body, dict):
            return _jsonrpc_error(
                None, ERROR_INVALID_REQUEST, "batch requests are not supported"
            )

        rpc_id = body.get("id")
        method = body.get("method")
        params = body.get("params") or {}
        if not isinstance(method, str):
            return _jsonrpc_error(rpc_id, ERROR_INVALID_REQUEST, "method is required")

        # 1. authenticate
        try:
            principal = gateway.authenticate(request)
        except AuthError:
            gateway.metrics.increment_request(
                metrics_module.OUTCOME_UNAUTHENTICATED
            )
            gateway.audit.append(
                request_id=trace_id,
                principal="-",
                role="-",
                tool=method,
                decision="unauthenticated",
                decision_code="invalid_api_key",
            )
            return _jsonrpc_error(
                rpc_id, ERROR_UNAUTHENTICATED, "invalid API key", status_code=401
            )

        if method == "initialize":
            return _jsonrpc_result(
                rpc_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            )

        if method not in ("tools/list", "tools/call"):
            return _jsonrpc_error(
                rpc_id, ERROR_METHOD_NOT_FOUND, f"method {method!r} is not supported"
            )

        # 2. rate limit
        rate = gateway.limiter.check(principal.key_id)
        if not rate.allowed:
            gateway.metrics.increment_request(metrics_module.OUTCOME_RATE_LIMITED)
            gateway.audit.append(
                request_id=trace_id,
                principal=principal.name,
                role=principal.role,
                tool=method,
                decision="rate_limited",
                decision_code="rate_limited",
            )
            return _jsonrpc_error(
                rpc_id,
                ERROR_RATE_LIMITED,
                f"rate limit exceeded, retry in {rate.retry_after_seconds:.1f}s",
                status_code=429,
                headers={"Retry-After": str(max(1, int(rate.retry_after_seconds) + 1))},
            )

        if method == "tools/list":
            return await _handle_tools_list(gateway, principal, rpc_id, trace_id)
        return await _handle_tools_call(gateway, principal, rpc_id, trace_id, params)

    return app


async def _handle_tools_list(
    gateway: Gateway, principal: Principal, rpc_id: Any, trace_id: str
) -> JSONResponse:
    started = time.perf_counter()
    try:
        tools = await gateway.proxy.list_tools(request_id=rpc_id)
    except UpstreamError as exc:
        gateway.metrics.increment_request(metrics_module.OUTCOME_UPSTREAM_ERROR)
        gateway.audit.append(
            request_id=trace_id,
            principal=principal.name,
            role=principal.role,
            tool="tools/list",
            decision="upstream_error",
            decision_code=str(exc.code),
        )
        return _jsonrpc_error(rpc_id, exc.code, exc.message, status_code=502)

    latency = time.perf_counter() - started
    gateway.metrics.observe_upstream_latency(latency)
    visible = gateway.policy.visible_tools(principal.role, tools)
    gateway.metrics.increment_request(metrics_module.OUTCOME_ALLOWED)
    gateway.audit.append(
        request_id=trace_id,
        principal=principal.name,
        role=principal.role,
        tool="tools/list",
        decision="allowed",
        decision_code=f"{len(visible)}_of_{len(tools)}_visible",
        latency_ms=round(latency * 1000, 3),
    )
    return _jsonrpc_result(rpc_id, {"tools": visible})


async def _handle_tools_call(
    gateway: Gateway,
    principal: Principal,
    rpc_id: Any,
    trace_id: str,
    params: Any,
) -> JSONResponse:
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        return _jsonrpc_error(
            rpc_id, ERROR_INVALID_PARAMS, "params.name is required and must be a string"
        )
    tool = params["name"]
    arguments = params.get("arguments") or {}

    # 3. authorize
    decision = gateway.policy.decide(principal.role, tool, arguments)
    if not decision.allowed:
        gateway.metrics.increment_request(metrics_module.OUTCOME_DENIED)
        gateway.audit.append(
            request_id=trace_id,
            principal=principal.name,
            role=principal.role,
            tool=tool,
            decision="denied",
            decision_code=decision.code,
        )
        return _jsonrpc_error(rpc_id, ERROR_FORBIDDEN, decision.reason, status_code=403)

    # 4. forward
    started = time.perf_counter()
    try:
        upstream, reply = await gateway.proxy.call_tool(tool, arguments, request_id=rpc_id)
    except UpstreamError as exc:
        gateway.metrics.increment_request(metrics_module.OUTCOME_UPSTREAM_ERROR)
        gateway.audit.append(
            request_id=trace_id,
            principal=principal.name,
            role=principal.role,
            tool=tool,
            decision="upstream_error",
            decision_code=str(exc.code),
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        return _jsonrpc_error(rpc_id, exc.code, exc.message, status_code=502)

    latency = time.perf_counter() - started
    gateway.metrics.observe_upstream_latency(latency)

    # 5. scan on the way out
    scan = gateway.scanner.scan(reply.get("result"))
    for finding in scan.findings:
        gateway.metrics.increment_finding(
            finding.detector, finding.severity, finding.count
        )
    findings = [finding.to_dict() for finding in scan.findings]

    if scan.blocked:
        gateway.metrics.increment_request(metrics_module.OUTCOME_BLOCKED)
        gateway.audit.append(
            request_id=trace_id,
            principal=principal.name,
            role=principal.role,
            tool=tool,
            decision="blocked",
            decision_code="high_severity_finding",
            upstream=upstream.name,
            latency_ms=round(latency * 1000, 3),
            findings=findings,
        )
        return _jsonrpc_error(
            rpc_id,
            ERROR_RESPONSE_BLOCKED,
            "response withheld: high-severity content finding",
        )

    gateway.metrics.increment_request(metrics_module.OUTCOME_ALLOWED)
    gateway.audit.append(
        request_id=trace_id,
        principal=principal.name,
        role=principal.role,
        tool=tool,
        decision="allowed",
        decision_code="ok",
        upstream=upstream.name,
        latency_ms=round(latency * 1000, 3),
        findings=findings,
    )

    if "error" in reply:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": rpc_id, "error": reply["error"]}
        )
    return _jsonrpc_result(rpc_id, scan.payload)



def build() -> FastAPI:  # pragma: no cover - entrypoint
    """uvicorn app.main:build --factory"""
    return create_app()
