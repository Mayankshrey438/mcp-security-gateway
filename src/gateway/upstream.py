from __future__ import annotations

from typing import Any

import httpx

from gateway.models import UpstreamConfig


class UpstreamError(RuntimeError):
    pass


class UpstreamRegistry:
    def __init__(
        self,
        configs: list[UpstreamConfig],
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._configs = {config.id: config for config in configs}
        self._client = client or httpx.AsyncClient()

    def get(self, server_id: str) -> UpstreamConfig | None:
        config = self._configs.get(server_id)
        return config if config and config.enabled else None

    async def call(
        self,
        server_id: str,
        message: dict[str, Any],
        protocol_version: str,
    ) -> dict[str, Any]:
        config = self.get(server_id)
        if not config:
            raise UpstreamError("unknown or disabled upstream")
        headers = {
            "Content-Type": "application/json",
            "MCP-Protocol-Version": protocol_version,
        }
        if config.bearer_token:
            headers["Authorization"] = f"Bearer {config.bearer_token}"
        try:
            response = await self._client.post(
                config.url,
                json=message,
                headers=headers,
                timeout=config.timeout_seconds,
            )
            response.raise_for_status()
            if response.status_code in {202, 204} or not response.content:
                return {
                    "_gateway_no_content": True,
                    "_gateway_status": response.status_code,
                }
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise UpstreamError("upstream request failed") from exc
        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
            raise UpstreamError("upstream returned an invalid JSON-RPC response")
        return payload

    async def close(self) -> None:
        await self._client.aclose()
