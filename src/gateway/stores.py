from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from gateway.models import Approval, ApprovalStatus, AuditEvent

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS approvals (
  id UUID PRIMARY KEY,
  payload JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL,
  correlation_id TEXT NOT NULL,
  payload JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_correlation_idx
  ON audit_events(correlation_id, occurred_at DESC);
CREATE TABLE IF NOT EXISTS tool_baselines (
  server_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  digest TEXT NOT NULL,
  approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(server_id, tool_name)
);
"""


class Repository(ABC):
    @abstractmethod
    async def initialize(self) -> None: ...

    @abstractmethod
    async def ready(self) -> bool: ...

    @abstractmethod
    async def create_approval(self, approval: Approval) -> Approval: ...

    @abstractmethod
    async def get_approval(self, approval_id: UUID) -> Approval | None: ...

    @abstractmethod
    async def decide_approval(
        self, approval_id: UUID, status: ApprovalStatus, decided_by: str, reason: str | None
    ) -> Approval | None: ...

    @abstractmethod
    async def consume_approval(self, approval_id: UUID) -> bool: ...

    @abstractmethod
    async def append_audit(self, event: AuditEvent) -> None: ...

    @abstractmethod
    async def list_audit(
        self, correlation_id: str | None = None, limit: int = 100
    ) -> list[AuditEvent]: ...

    @abstractmethod
    async def get_tool_digest(self, server_id: str, tool_name: str) -> str | None: ...

    @abstractmethod
    async def set_tool_digest(self, server_id: str, tool_name: str, digest: str) -> None: ...


class MemoryRepository(Repository):
    def __init__(self) -> None:
        self.approvals: dict[UUID, Approval] = {}
        self.audit: list[AuditEvent] = []
        self.tool_digests: dict[tuple[str, str], str] = {}
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        return None

    async def ready(self) -> bool:
        return True

    async def create_approval(self, approval: Approval) -> Approval:
        async with self._lock:
            self.approvals[approval.id] = approval
        return approval

    async def get_approval(self, approval_id: UUID) -> Approval | None:
        approval = self.approvals.get(approval_id)
        if approval and approval.expires_at <= datetime.now(UTC):
            approval.status = ApprovalStatus.EXPIRED
        return approval

    async def decide_approval(
        self, approval_id: UUID, status: ApprovalStatus, decided_by: str, reason: str | None
    ) -> Approval | None:
        async with self._lock:
            approval = await self.get_approval(approval_id)
            if not approval or approval.status != ApprovalStatus.PENDING:
                return None
            approval.status = status
            approval.decided_by = decided_by
            approval.decided_at = datetime.now(UTC)
            approval.reason = reason
            return approval

    async def consume_approval(self, approval_id: UUID) -> bool:
        async with self._lock:
            approval = await self.get_approval(approval_id)
            if not approval or approval.status != ApprovalStatus.APPROVED:
                return False
            approval.status = ApprovalStatus.CONSUMED
            return True

    async def append_audit(self, event: AuditEvent) -> None:
        self.audit.append(event)

    async def list_audit(
        self, correlation_id: str | None = None, limit: int = 100
    ) -> list[AuditEvent]:
        events = self.audit
        if correlation_id:
            events = [item for item in events if item.correlation_id == correlation_id]
        return list(reversed(events[-limit:]))

    async def get_tool_digest(self, server_id: str, tool_name: str) -> str | None:
        return self.tool_digests.get((server_id, tool_name))

    async def set_tool_digest(self, server_id: str, tool_name: str, digest: str) -> None:
        self.tool_digests[(server_id, tool_name)] = digest


class PostgresRepository(Repository):
    def __init__(self, database_url: str) -> None:
        self.engine: AsyncEngine = create_async_engine(database_url, pool_pre_ping=True)

    async def initialize(self) -> None:
        async with self.engine.begin() as connection:
            for statement in SCHEMA_SQL.strip().split(";"):
                if statement.strip():
                    await connection.execute(text(statement))

    async def ready(self) -> bool:
        try:
            async with self.engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    async def create_approval(self, approval: Approval) -> Approval:
        async with self.engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO approvals(id, payload) VALUES (:id, CAST(:payload AS JSONB))"),
                {"id": approval.id, "payload": approval.model_dump_json()},
            )
        return approval

    async def get_approval(self, approval_id: UUID) -> Approval | None:
        async with self.engine.connect() as connection:
            row = (
                await connection.execute(
                    text("SELECT payload FROM approvals WHERE id=:id"), {"id": approval_id}
                )
            ).first()
        if not row:
            return None
        approval = Approval.model_validate(row.payload)
        if approval.expires_at <= datetime.now(UTC) and approval.status in {
            ApprovalStatus.PENDING,
            ApprovalStatus.APPROVED,
        }:
            approval.status = ApprovalStatus.EXPIRED
        return approval

    async def decide_approval(
        self, approval_id: UUID, status: ApprovalStatus, decided_by: str, reason: str | None
    ) -> Approval | None:
        async with self.engine.begin() as connection:
            row = (
                await connection.execute(
                    text("SELECT payload FROM approvals WHERE id=:id FOR UPDATE"),
                    {"id": approval_id},
                )
            ).first()
            if not row:
                return None
            approval = Approval.model_validate(row.payload)
            if (
                approval.expires_at <= datetime.now(UTC)
                or approval.status != ApprovalStatus.PENDING
            ):
                return None
            approval.status = status
            approval.decided_at = datetime.now(UTC)
            approval.decided_by = decided_by
            approval.reason = reason
            await connection.execute(
                text("UPDATE approvals SET payload=CAST(:payload AS JSONB) WHERE id=:id"),
                {"id": approval_id, "payload": approval.model_dump_json()},
            )
            return approval

    async def consume_approval(self, approval_id: UUID) -> bool:
        async with self.engine.begin() as connection:
            row = (
                await connection.execute(
                    text("SELECT payload FROM approvals WHERE id=:id FOR UPDATE"),
                    {"id": approval_id},
                )
            ).first()
            if not row:
                return False
            approval = Approval.model_validate(row.payload)
            if approval.status != ApprovalStatus.APPROVED or approval.expires_at <= datetime.now(
                UTC
            ):
                return False
            approval.status = ApprovalStatus.CONSUMED
            await connection.execute(
                text("UPDATE approvals SET payload=CAST(:payload AS JSONB) WHERE id=:id"),
                {"id": approval_id, "payload": approval.model_dump_json()},
            )
            return True

    async def append_audit(self, event: AuditEvent) -> None:
        async with self.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO audit_events(id, occurred_at, correlation_id, payload) "
                    "VALUES (:id, :occurred_at, :correlation_id, CAST(:payload AS JSONB))"
                ),
                {
                    "id": event.id,
                    "occurred_at": event.occurred_at,
                    "correlation_id": event.correlation_id,
                    "payload": event.model_dump_json(),
                },
            )

    async def list_audit(
        self, correlation_id: str | None = None, limit: int = 100
    ) -> list[AuditEvent]:
        query = "SELECT payload FROM audit_events"
        params: dict[str, object] = {"limit": limit}
        if correlation_id:
            query += " WHERE correlation_id=:correlation_id"
            params["correlation_id"] = correlation_id
        query += " ORDER BY occurred_at DESC LIMIT :limit"
        async with self.engine.connect() as connection:
            rows = (await connection.execute(text(query), params)).all()
        return [AuditEvent.model_validate(row.payload) for row in rows]

    async def get_tool_digest(self, server_id: str, tool_name: str) -> str | None:
        async with self.engine.connect() as connection:
            row = (
                await connection.execute(
                    text(
                        "SELECT digest FROM tool_baselines "
                        "WHERE server_id=:server_id AND tool_name=:tool_name"
                    ),
                    {"server_id": server_id, "tool_name": tool_name},
                )
            ).first()
        return row.digest if row else None

    async def set_tool_digest(self, server_id: str, tool_name: str, digest: str) -> None:
        async with self.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO tool_baselines(server_id, tool_name, digest) "
                    "VALUES (:server_id, :tool_name, :digest) "
                    "ON CONFLICT(server_id, tool_name) DO UPDATE "
                    "SET digest=:digest, approved_at=now()"
                ),
                {"server_id": server_id, "tool_name": tool_name, "digest": digest},
            )


class RateLimiter(ABC):
    @abstractmethod
    async def allow(self, key: str, limit: int, window_seconds: int) -> bool: ...

    @abstractmethod
    async def ready(self) -> bool: ...


class MemoryRateLimiter(RateLimiter):
    def __init__(self) -> None:
        self._buckets: dict[str, tuple[int, float]] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        async with self._lock:
            count, expires = self._buckets.get(key, (0, time.monotonic() + window_seconds))
            if time.monotonic() >= expires:
                count, expires = 0, time.monotonic() + window_seconds
            count += 1
            self._buckets[key] = (count, expires)
            return count <= limit

    async def ready(self) -> bool:
        return True


class RedisRateLimiter(RateLimiter):
    def __init__(self, redis_url: str) -> None:
        self.redis = Redis.from_url(redis_url, decode_responses=True)

    async def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        bucket = f"mcp-gateway:rate:{key}:{int(time.time() // window_seconds)}"
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.incr(bucket)
            pipe.expire(bucket, window_seconds + 1)
            count, _ = await pipe.execute()
        return int(count) <= limit

    async def ready(self) -> bool:
        try:
            return bool(await self.redis.ping())
        except Exception:
            return False
