# MCP Security Gateway

A fail-closed security proxy between AI agents and Model Context Protocol (MCP)
servers. The gateway exposes an MCP-compatible endpoint, evaluates every tool
call with deterministic policy, and forwards only authorized requests.

## Security invariant

**A denied, malformed, changed, rate-limited, or unapproved tool call never
reaches the upstream MCP server.**

Prompt-injection scanning is defense in depth. It is not used as the
authorization boundary.

## Architecture

```text
MCP host/agent
    -> identity and transport validation
    -> tool integrity and JSON Schema validation
    -> deterministic policy
    -> rate limit
    -> optional human approval
    -> upstream MCP server
    -> output validation and injection scan
    -> redacted audit event
```

The HTTP endpoint is `POST /mcp/{server_id}`. The management API is under
`/v1`. A line-delimited JSON stdio adapter is also included.

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

Run locally without infrastructure:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
MCP_GATEWAY_DEV_IDENTITY=true uvicorn gateway.main:app --reload
pytest
```

The development identity mode accepts `X-Agent-ID`; it is disabled by default
and must never be used for an internet-facing deployment. Production HTTP
deployments validate JWT signatures, issuer, audience, and expiry.

Automatic trust-on-first-use for tool definitions is also disabled by default.
Administrators review `/v1/tool-baselines/pending` and approve an exact digest.
The Docker demo enables enrollment only to keep the one-command walkthrough
self-contained.

## Example policy

`policies/default.yaml` allows `research-agent` to call `read_file` only below
`/docs`, requires approval for `send_email`, and denies everything else.
Rules are first-match; the default decision is deny.

## Approval safety

An approval is bound to the authenticated principal, server, tool, canonical
argument hash, policy version, and expiration. It is single-use. Changing any
argument invalidates it.

## Verification

```bash
ruff check .
pytest --cov=gateway
python benchmarks/load.py --requests 1000 --concurrency 20
```

See `docs/compatibility.md`, `docs/threat-model.md`, and `openapi.yaml` for the
protocol and management contracts.
