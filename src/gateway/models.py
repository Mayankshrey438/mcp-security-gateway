from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Principal(BaseModel):
    id: str
    tenant_id: str = "default"
    scopes: frozenset[str] = frozenset()
    claims: dict[str, Any] = Field(default_factory=dict)


class JsonRpcRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    jsonrpc: Literal["2.0"]
    method: str
    id: str | int | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class DecisionKind(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class PolicyDecision(BaseModel):
    decision: DecisionKind
    reason: str
    rule_id: str | None = None
    policy_version: str
    rate_limit: int | None = None
    rate_window_seconds: int = 60
    redact_fields: list[str] = Field(default_factory=list)


class PolicyContext(BaseModel):
    principal: Principal
    server_id: str
    method: str
    tool_name: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    tool_digest: str | None = None
    transport: Literal["http", "stdio"]
    correlation_id: str


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class Approval(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    principal_id: str
    server_id: str
    tool_name: str
    argument_hash: str
    policy_version: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    decided_at: datetime | None = None
    decided_by: str | None = None
    reason: str | None = None


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    reason: str | None = Field(default=None, max_length=500)


class AuditEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str
    principal_id: str
    tenant_id: str
    server_id: str
    method: str
    tool_name: str | None = None
    decision: str
    reason: str
    policy_version: str | None = None
    argument_hash: str | None = None
    tool_digest: str | None = None
    latency_ms: float | None = None
    upstream_status: str | None = None
    result_flagged: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolDefinition(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=dict)
    outputSchema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None


class UpstreamConfig(BaseModel):
    id: str
    url: str
    enabled: bool = True
    bearer_token: str | None = None
    timeout_seconds: float = 30.0


def rpc_error(
    request_id: str | int | None,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}
