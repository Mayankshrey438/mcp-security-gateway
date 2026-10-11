from __future__ import annotations

import asyncio
import json
import os
import sys

import httpx


async def proxy() -> None:
    """Bridge line-delimited stdio JSON-RPC to the gateway's HTTP endpoint."""
    endpoint = os.environ.get("MCP_GATEWAY_STDIO_URL", "http://127.0.0.1:8080/mcp/local")
    agent_id = os.environ.get("MCP_GATEWAY_STDIO_AGENT_ID")
    protocol_version = os.environ.get("MCP_GATEWAY_STDIO_PROTOCOL_VERSION", "2026-07-28")
    if not agent_id:
        raise RuntimeError("MCP_GATEWAY_STDIO_AGENT_ID is required")
    headers = {
        "Content-Type": "application/json",
        "MCP-Protocol-Version": protocol_version,
        "X-Agent-ID": agent_id,
        "X-Agent-Scopes": os.environ.get("MCP_GATEWAY_STDIO_AGENT_SCOPES", ""),
    }
    async with httpx.AsyncClient(timeout=60) as client:
        while line := await asyncio.to_thread(sys.stdin.readline):
            try:
                payload = json.loads(line)
                response = await client.post(endpoint, json=payload, headers=headers)
                response.raise_for_status()
                if response.status_code in {202, 204} or not response.content:
                    continue
                output = response.json()
            except Exception as exc:
                output = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32006, "message": f"stdio gateway error: {exc}"},
                }
            sys.stdout.write(json.dumps(output, separators=(",", ":")) + "\n")
            sys.stdout.flush()


def run() -> None:
    asyncio.run(proxy())


if __name__ == "__main__":
    run()
