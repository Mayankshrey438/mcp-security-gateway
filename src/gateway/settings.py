from __future__ import annotations

import json
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from gateway.models import UpstreamConfig


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MCP_GATEWAY_",
        env_file=".env",
        extra="ignore",
    )

    host: str = "127.0.0.1"
    port: int = 8080
    policy_path: str = "policies/default.yaml"
    database_url: str = "postgresql+asyncpg://gateway:gateway@postgres:5432/gateway"
    redis_url: str = "redis://redis:6379/0"
    use_memory_stores: bool = False
    dev_identity: bool = False
    jwt_public_key: str | None = None
    jwt_algorithm: str = "RS256"
    jwt_issuer: str = "https://identity.example.com"
    jwt_audience: str = "mcp-security-gateway"
    admin_scope: str = "gateway:admin"
    protocol_versions: list[str] = Field(default_factory=lambda: ["2026-07-28"])
    allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://127.0.0.1", "http://localhost"]
    )
    max_request_bytes: int = 1_048_576
    max_result_bytes: int = 4_194_304
    approval_ttl_seconds: int = 300
    block_flagged_results: bool = True
    allow_tool_enrollment: bool = False
    otlp_endpoint: str | None = None
    upstreams: list[UpstreamConfig] = Field(default_factory=list)

    @field_validator("protocol_versions", "allowed_origins", mode="before")
    @classmethod
    def parse_versions(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("upstreams", mode="before")
    @classmethod
    def parse_upstreams(cls, value: object) -> object:
        if isinstance(value, str):
            return json.loads(value)
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
