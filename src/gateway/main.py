from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from gateway.integrity import tool_digest
from gateway.models import ApprovalDecisionRequest, ApprovalStatus, rpc_error
from gateway.observability import configure_observability
from gateway.policy import PolicyEngine
from gateway.security import IdentityVerifier
from gateway.service import GatewayService
from gateway.settings import Settings, get_settings
from gateway.stores import (
    MemoryRateLimiter,
    MemoryRepository,
    PostgresRepository,
    RedisRateLimiter,
    Repository,
)
from gateway.upstream import UpstreamRegistry


def build_dependencies(settings: Settings) -> tuple[GatewayService, Repository]:
    repository: Repository
    if settings.use_memory_stores:
        repository = MemoryRepository()
        limiter = MemoryRateLimiter()
    else:
        repository = PostgresRepository(settings.database_url)
        limiter = RedisRateLimiter(settings.redis_url)
    policy = PolicyEngine.from_path(settings.policy_path)
    service = GatewayService(
        settings=settings,
        policy=policy,
        repository=repository,
        limiter=limiter,
        upstreams=UpstreamRegistry(settings.upstreams),
    )
    return service, repository


def create_app(
    settings: Settings | None = None,
    service: GatewayService | None = None,
    repository: Repository | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    if service is None or repository is None:
        service, repository = build_dependencies(settings)
    verifier = IdentityVerifier(settings)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.initialization_error = None
        try:
            await repository.initialize()
        except Exception as exc:
            application.state.initialization_error = str(exc)
        yield
        await service.upstreams.close()

    application = FastAPI(
        title="MCP Security Gateway",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.state.gateway = service
    application.state.repository = repository

    @application.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/health/ready")
    async def ready() -> Response:
        initialized = application.state.initialization_error is None
        dependencies_ready = await repository.ready() and await service.limiter.ready()
        if initialized and dependencies_ready:
            return JSONResponse({"status": "ok"})
        return JSONResponse({"status": "unavailable"}, status_code=503)

    @application.get("/metrics")
    async def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @application.post("/mcp/{server_id}")
    async def mcp(server_id: str, request: Request) -> Response:
        origin = request.headers.get("Origin")
        if origin and origin not in settings.allowed_origins:
            raise HTTPException(status_code=403, detail="Origin is not allowed")
        content_length = request.headers.get("Content-Length")
        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc
            if declared_size > settings.max_request_bytes:
                raise HTTPException(status_code=413, detail="Request too large")
        body = await request.body()
        if len(body) > settings.max_request_bytes:
            raise HTTPException(status_code=413, detail="Request too large")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return JSONResponse(rpc_error(None, -32700, "Parse error"))
        if not isinstance(payload, dict):
            return JSONResponse(rpc_error(None, -32600, "Batch requests are not supported"))
        protocol_version = request.headers.get("MCP-Protocol-Version")
        if not protocol_version or protocol_version not in settings.protocol_versions:
            return JSONResponse(
                rpc_error(
                    payload.get("id"),
                    -32600,
                    "Unsupported MCP protocol version",
                    {"supported_versions": settings.protocol_versions},
                ),
                status_code=400,
            )
        embedded_version = _embedded_protocol_version(payload)
        if embedded_version and embedded_version != protocol_version:
            return JSONResponse(
                rpc_error(payload.get("id"), -32600, "MCP protocol header mismatch"),
                status_code=400,
            )
        principal = verifier.verify_http(request)
        result = await service.handle(
            server_id=server_id,
            raw=payload,
            principal=principal,
            protocol_version=protocol_version,
            transport="http",
            correlation_id=request.headers.get("X-Correlation-ID", ""),
        )
        if result.pop("_gateway_no_content", False):
            return Response(status_code=int(result.get("_gateway_status", 202)))
        return JSONResponse(result)

    @application.get("/v1/approvals/{approval_id}")
    async def get_approval(approval_id: UUID, request: Request) -> Any:
        verifier.require_admin(request)
        approval = await repository.get_approval(approval_id)
        if not approval:
            raise HTTPException(status_code=404, detail="Approval not found")
        return approval

    @application.post("/v1/approvals/{approval_id}/decision")
    async def decide_approval(
        approval_id: UUID, decision: ApprovalDecisionRequest, request: Request
    ) -> Any:
        administrator = verifier.require_admin(request)
        status = (
            ApprovalStatus.APPROVED if decision.decision == "approved" else ApprovalStatus.REJECTED
        )
        approval = await repository.decide_approval(
            approval_id, status, administrator.id, decision.reason
        )
        if not approval:
            raise HTTPException(status_code=409, detail="Approval cannot be decided")
        return approval

    @application.get("/v1/audit")
    async def audit(
        request: Request,
        correlation_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> Any:
        verifier.require_admin(request)
        return await repository.list_audit(correlation_id, limit)

    @application.get("/v1/tool-baselines/pending")
    async def pending_tool_baselines(request: Request) -> Any:
        verifier.require_admin(request)
        pending: list[dict[str, Any]] = []
        for (server_id, tool_name), tool in service.tools.items():
            digest = tool_digest(tool)
            baseline = await repository.get_tool_digest(server_id, tool_name)
            if baseline != digest:
                pending.append(
                    {
                        "server_id": server_id,
                        "tool": tool.model_dump(by_alias=True),
                        "digest": digest,
                        "previous_digest": baseline,
                    }
                )
        return pending

    @application.post("/v1/tool-baselines/{server_id}/{tool_name}/approve")
    async def approve_tool_baseline(server_id: str, tool_name: str, request: Request) -> Any:
        administrator = verifier.require_admin(request)
        tool = service.tools.get((server_id, tool_name))
        if not tool:
            raise HTTPException(status_code=404, detail="Discovered tool not found")
        digest = tool_digest(tool)
        await repository.set_tool_digest(server_id, tool_name, digest)
        return {
            "server_id": server_id,
            "tool_name": tool_name,
            "digest": digest,
            "approved_by": administrator.id,
        }

    configure_observability(application, settings.otlp_endpoint)
    return application


def _embedded_protocol_version(payload: dict[str, Any]) -> str | None:
    metadata = payload.get("_meta")
    if not isinstance(metadata, dict):
        return None
    capabilities = metadata.get("io.modelcontextprotocol/clientCapabilities")
    if not isinstance(capabilities, dict):
        return None
    version = capabilities.get("protocolVersion")
    return version if isinstance(version, str) else None


app = create_app()


def run() -> None:
    settings = get_settings()
    uvicorn.run("gateway.main:app", host=settings.host, port=settings.port)
