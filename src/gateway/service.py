from __future__ import annotations

import copy
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from jsonschema import Draft202012Validator

from gateway.integrity import ToolIntegrity
from gateway.metrics import LATENCY, POLICY_LATENCY, REQUESTS, RESULT_FLAGS
from gateway.models import (
    Approval,
    ApprovalStatus,
    AuditEvent,
    DecisionKind,
    JsonRpcRequest,
    PolicyContext,
    Principal,
    ToolDefinition,
    rpc_error,
)
from gateway.policy import PolicyEngine
from gateway.scanning import redact, scan_result, validate_output
from gateway.security import stable_hash
from gateway.settings import Settings
from gateway.stores import RateLimiter, Repository
from gateway.upstream import UpstreamError, UpstreamRegistry


class GatewayService:
    def __init__(
        self,
        settings: Settings,
        policy: PolicyEngine,
        repository: Repository,
        limiter: RateLimiter,
        upstreams: UpstreamRegistry,
    ) -> None:
        self.settings = settings
        self.policy = policy
        self.repository = repository
        self.limiter = limiter
        self.upstreams = upstreams
        self.integrity = ToolIntegrity(repository)
        self.tools: dict[tuple[str, str], ToolDefinition] = {}

    async def handle(
        self,
        server_id: str,
        raw: dict[str, Any],
        principal: Principal,
        protocol_version: str,
        transport: str = "http",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            request = JsonRpcRequest.model_validate(raw)
        except Exception:
            return rpc_error(raw.get("id"), -32600, "Invalid JSON-RPC request")
        correlation_id = (
            correlation_id
            or stable_hash({"principal": principal.id, "id": request.id, "time": time.time_ns()})[
                :24
            ]
        )
        tool_name = self._tool_name(request)
        argument_hash = stable_hash(self._arguments(request)) if tool_name else None
        audit = AuditEvent(
            correlation_id=correlation_id,
            principal_id=principal.id,
            tenant_id=principal.tenant_id,
            server_id=server_id,
            method=request.method,
            tool_name=tool_name,
            decision="error",
            reason="request did not complete",
            argument_hash=argument_hash,
        )
        if not await self.repository.ready() or not await self.limiter.ready():
            audit.decision = "deny"
            audit.reason = "required policy infrastructure is unavailable"
            REQUESTS.labels(request.method, "deny").inc()
            return rpc_error(
                request.id,
                -32006,
                "Required policy infrastructure is unavailable; request failed closed",
            )

        with LATENCY.labels(request.method).time():
            try:
                if not self.upstreams.get(server_id):
                    return await self._deny(request, audit, -32004, "Unknown or disabled upstream")
                if request.method == "tools/list":
                    response = await self.upstreams.call(server_id, raw, protocol_version)
                    return await self._filter_tool_list(response, server_id, principal, audit)
                if request.method != "tools/call":
                    context = self._context(
                        principal, server_id, request, transport, correlation_id, None
                    )
                    decision = self._evaluate(context)
                    if decision.decision != DecisionKind.ALLOW:
                        return await self._deny(request, audit, -32001, decision.reason)
                    response = await self.upstreams.call(server_id, raw, protocol_version)
                    audit.decision = "allow"
                    audit.reason = decision.reason
                    audit.policy_version = decision.policy_version
                    return response

                if not tool_name:
                    return await self._deny(request, audit, -32602, "Missing tool name")
                tool = await self._get_tool(server_id, tool_name, protocol_version)
                if not tool:
                    return await self._deny(request, audit, -32602, "Unknown tool")
                integrity_ok, digest = await self.integrity.verify_or_enroll(
                    server_id, tool, allow_enrollment=self.settings.allow_tool_enrollment
                )
                audit.tool_digest = digest
                if not integrity_ok:
                    return await self._deny(
                        request, audit, -32005, "Tool definition changed; review required"
                    )
                schema_errors = [
                    error.message
                    for error in Draft202012Validator(tool.inputSchema).iter_errors(
                        self._arguments(request)
                    )
                ]
                if schema_errors:
                    return await self._deny(
                        request,
                        audit,
                        -32602,
                        "Tool input schema validation failed",
                        {"errors": schema_errors[:10]},
                    )
                context = self._context(
                    principal, server_id, request, transport, correlation_id, digest
                )
                decision = self._evaluate(context)
                audit.policy_version = decision.policy_version
                audit.metadata["arguments"] = redact(
                    self._arguments(request), decision.redact_fields
                )
                if decision.decision == DecisionKind.DENY:
                    return await self._deny(request, audit, -32001, decision.reason)
                if decision.rate_limit and not await self.limiter.allow(
                    f"{principal.tenant_id}:{principal.id}:{server_id}:{tool_name}",
                    decision.rate_limit,
                    decision.rate_window_seconds,
                ):
                    return await self._deny(request, audit, -32003, "Rate limit exceeded")
                if decision.decision == DecisionKind.REQUIRE_APPROVAL:
                    approved = await self._consume_bound_approval(
                        request, principal, server_id, tool_name, decision.policy_version
                    )
                    if not approved:
                        approval = await self._create_approval(
                            principal, server_id, tool_name, decision.policy_version, request
                        )
                        return await self._deny(
                            request,
                            audit,
                            -32002,
                            "Human approval required",
                            {
                                "approval_id": str(approval.id),
                                "expires_at": approval.expires_at.isoformat(),
                            },
                        )

                forwarded = self._without_gateway_metadata(raw)
                response = await self.upstreams.call(server_id, forwarded, protocol_version)
                checked, released = await self._check_result(request, response, tool, audit)
                if not released:
                    REQUESTS.labels(request.method, "quarantine").inc()
                    return checked
                audit.decision = "allow"
                audit.reason = decision.reason
                REQUESTS.labels(request.method, "allow").inc()
                return checked
            except UpstreamError as exc:
                return await self._deny(request, audit, -32006, str(exc))
            finally:
                audit.latency_ms = (time.perf_counter() - started) * 1000
                await self.repository.append_audit(audit)

    def _evaluate(self, context: PolicyContext):
        with POLICY_LATENCY.time():
            return self.policy.evaluate(context)

    async def _filter_tool_list(
        self,
        response: dict[str, Any],
        server_id: str,
        principal: Principal,
        audit: AuditEvent,
    ) -> tuple[dict[str, Any], bool]:
        result = response.get("result")
        tools_raw = result.get("tools", []) if isinstance(result, dict) else []
        valid: list[tuple[ToolDefinition, dict[str, Any]]] = []
        for raw_tool in tools_raw:
            try:
                tool = ToolDefinition.model_validate(raw_tool)
            except Exception:
                continue
            self.tools[(server_id, tool.name)] = tool
            ok, _ = await self.integrity.verify_or_enroll(
                server_id, tool, allow_enrollment=self.settings.allow_tool_enrollment
            )
            if ok:
                valid.append((tool, raw_tool))
        visible = self.policy.visible_tools(
            principal.id, server_id, principal.scopes, [tool.name for tool, _ in valid]
        )
        filtered = copy.deepcopy(response)
        filtered.setdefault("result", {})["tools"] = [
            raw_tool for tool, raw_tool in valid if tool.name in visible
        ]
        audit.decision = "allow"
        audit.reason = f"returned {len(filtered['result']['tools'])} permitted tools"
        audit.policy_version = self.policy.document.version
        REQUESTS.labels("tools/list", "allow").inc()
        return filtered

    async def _get_tool(
        self, server_id: str, tool_name: str, protocol_version: str
    ) -> ToolDefinition | None:
        cached = self.tools.get((server_id, tool_name))
        if cached:
            return cached
        response = await self.upstreams.call(
            server_id,
            {"jsonrpc": "2.0", "id": "gateway-discovery", "method": "tools/list", "params": {}},
            protocol_version,
        )
        result = response.get("result", {})
        for raw_tool in result.get("tools", []) if isinstance(result, dict) else []:
            try:
                tool = ToolDefinition.model_validate(raw_tool)
            except Exception:
                continue
            self.tools[(server_id, tool.name)] = tool
        return self.tools.get((server_id, tool_name))

    async def _check_result(
        self,
        request: JsonRpcRequest,
        response: dict[str, Any],
        tool: ToolDefinition,
        audit: AuditEvent,
    ) -> dict[str, Any]:
        encoded = json.dumps(response, ensure_ascii=False).encode()
        if len(encoded) > self.settings.max_result_bytes:
            return rpc_error(request.id, -32007, "Tool result exceeds configured size limit"), False
        result = response.get("result")
        structured = result.get("structuredContent") if isinstance(result, dict) else result
        output_errors = validate_output(structured, tool.outputSchema)
        if output_errors:
            return (
                rpc_error(
                    request.id,
                    -32007,
                    "Tool output schema validation failed",
                    {"errors": output_errors[:10]},
                ),
                False,
            )
        scan = scan_result(result)
        audit.result_flagged = scan.flagged
        if scan.flagged:
            RESULT_FLAGS.labels(audit.server_id, tool.name).inc()
            if self.settings.block_flagged_results:
                audit.decision = "quarantine"
                audit.reason = "result matched injection heuristics"
                return (
                    rpc_error(
                        request.id,
                        -32007,
                        "Tool result quarantined",
                        {"reasons": scan.reasons},
                    ),
                    False,
                )
        return response, True

    async def _create_approval(
        self,
        principal: Principal,
        server_id: str,
        tool_name: str,
        policy_version: str,
        request: JsonRpcRequest,
    ) -> Approval:
        approval = Approval(
            principal_id=principal.id,
            server_id=server_id,
            tool_name=tool_name,
            argument_hash=stable_hash(self._arguments(request)),
            policy_version=policy_version,
            expires_at=datetime.now(UTC) + timedelta(seconds=self.settings.approval_ttl_seconds),
        )
        return await self.repository.create_approval(approval)

    async def _consume_bound_approval(
        self,
        request: JsonRpcRequest,
        principal: Principal,
        server_id: str,
        tool_name: str,
        policy_version: str,
    ) -> bool:
        metadata = request.params.get("_meta", {})
        approval_value = metadata.get("gatewayApprovalId") if isinstance(metadata, dict) else None
        if not approval_value:
            return False
        try:
            approval_id = UUID(str(approval_value))
        except ValueError:
            return False
        approval = await self.repository.get_approval(approval_id)
        if not approval:
            return False
        expected = (
            approval.principal_id == principal.id
            and approval.server_id == server_id
            and approval.tool_name == tool_name
            and approval.argument_hash == stable_hash(self._arguments(request))
            and approval.policy_version == policy_version
            and approval.status == ApprovalStatus.APPROVED
        )
        return expected and await self.repository.consume_approval(approval_id)

    async def _deny(
        self,
        request: JsonRpcRequest,
        audit: AuditEvent,
        code: int,
        reason: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        audit.decision = "deny"
        audit.reason = reason
        REQUESTS.labels(request.method, "deny").inc()
        return rpc_error(request.id, code, reason, data)

    @staticmethod
    def _tool_name(request: JsonRpcRequest) -> str | None:
        name = request.params.get("name")
        return name if isinstance(name, str) else None

    @staticmethod
    def _arguments(request: JsonRpcRequest) -> dict[str, Any]:
        arguments = request.params.get("arguments", {})
        return arguments if isinstance(arguments, dict) else {}

    @staticmethod
    def _without_gateway_metadata(raw: dict[str, Any]) -> dict[str, Any]:
        forwarded = copy.deepcopy(raw)
        params = forwarded.get("params")
        if isinstance(params, dict) and isinstance(params.get("_meta"), dict):
            params["_meta"].pop("gatewayApprovalId", None)
            if not params["_meta"]:
                params.pop("_meta")
        return forwarded

    @staticmethod
    def _context(
        principal: Principal,
        server_id: str,
        request: JsonRpcRequest,
        transport: str,
        correlation_id: str,
        digest: str | None,
    ) -> PolicyContext:
        return PolicyContext(
            principal=principal,
            server_id=server_id,
            method=request.method,
            tool_name=GatewayService._tool_name(request),
            arguments=GatewayService._arguments(request),
            tool_digest=digest,
            transport="stdio" if transport == "stdio" else "http",
            correlation_id=correlation_id,
        )
