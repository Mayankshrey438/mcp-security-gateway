from __future__ import annotations

import httpx
import pytest

from gateway.main import create_app
from gateway.models import ToolDefinition, UpstreamConfig
from gateway.policy import PolicyDocument, PolicyEngine
from gateway.service import GatewayService
from gateway.settings import Settings
from gateway.stores import MemoryRateLimiter, MemoryRepository
from gateway.upstream import UpstreamRegistry


@pytest.mark.asyncio
async def test_http_rejects_bad_origin_before_upstream() -> None:
    upstream_calls = 0

    async def upstream(_: httpx.Request) -> httpx.Response:
        nonlocal upstream_calls
        upstream_calls += 1
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    settings = Settings(
        use_memory_stores=True,
        dev_identity=True,
        allowed_origins=["http://localhost"],
        upstreams=[UpstreamConfig(id="test", url="https://upstream.test/mcp")],
    )
    repository = MemoryRepository()
    service = GatewayService(
        settings,
        PolicyEngine(PolicyDocument(version="test", rules=[])),
        repository,
        MemoryRateLimiter(),
        UpstreamRegistry(
            settings.upstreams,
            httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
        ),
    )
    app = create_app(settings, service, repository)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        response = await client.post(
            "/mcp/test",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={
                "Origin": "https://attacker.example",
                "MCP-Protocol-Version": "2026-07-28",
                "X-Agent-ID": "agent",
            },
        )
    await service.upstreams.close()
    assert response.status_code == 403
    assert upstream_calls == 0


@pytest.mark.asyncio
async def test_http_requires_supported_protocol_version() -> None:
    settings = Settings(use_memory_stores=True, dev_identity=True, upstreams=[])
    repository = MemoryRepository()
    service = GatewayService(
        settings,
        PolicyEngine(PolicyDocument(version="test", rules=[])),
        repository,
        MemoryRateLimiter(),
        UpstreamRegistry([]),
    )
    app = create_app(settings, service, repository)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        response = await client.post(
            "/mcp/test",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"MCP-Protocol-Version": "1900-01-01", "X-Agent-ID": "agent"},
        )
    await service.upstreams.close()
    assert response.status_code == 400
    assert response.json()["error"]["message"] == "Unsupported MCP protocol version"


@pytest.mark.asyncio
async def test_admin_can_approve_exact_discovered_tool_digest() -> None:
    settings = Settings(use_memory_stores=True, dev_identity=True, upstreams=[])
    repository = MemoryRepository()
    service = GatewayService(
        settings,
        PolicyEngine(PolicyDocument(version="test", rules=[])),
        repository,
        MemoryRateLimiter(),
        UpstreamRegistry([]),
    )
    service.tools[("filesystem", "read_file")] = ToolDefinition(
        name="read_file",
        description="Read a file",
        inputSchema={"type": "object"},
    )
    app = create_app(settings, service, repository)
    headers = {"X-Agent-ID": "admin", "X-Agent-Scopes": "gateway:admin"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        pending = await client.get("/v1/tool-baselines/pending", headers=headers)
        approved = await client.post(
            "/v1/tool-baselines/filesystem/read_file/approve", headers=headers
        )
    await service.upstreams.close()
    assert pending.status_code == 200
    assert len(pending.json()) == 1
    assert approved.status_code == 200
    assert await repository.get_tool_digest("filesystem", "read_file") == approved.json()["digest"]
