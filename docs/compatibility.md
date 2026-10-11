# MCP compatibility contract

## Supported surface

- JSON-RPC 2.0 request, response, notification, and error envelopes.
- MCP protocol versions configured in `MCP_GATEWAY_PROTOCOL_VERSIONS`.
- Streamable HTTP `POST /mcp/{server_id}` with `MCP-Protocol-Version`.
- Stdio line-delimited JSON adapter for local MCP servers.
- `tools/list`, `tools/call`, initialization/discovery messages, notifications,
  and other methods that a policy permits.
- Request IDs and upstream JSON-RPC errors are preserved.
- HTTP deadlines are propagated to upstream requests.

## Gateway-owned behavior

- Invalid JSON-RPC: `-32600`.
- Unknown or disabled upstream: `-32004`.
- Authentication failure: HTTP 401/403.
- Policy denial: `-32001`.
- Approval required: `-32002`, including an approval request ID.
- Rate limit: `-32003`.
- Tool definition changed: `-32005`.
- Upstream unavailable or timed out: `-32006`.
- Unsafe result quarantined: `-32007`.

## Deliberate MVP limits

- HTTP responses are buffered so the full tool result can be validated.
- SSE subscription relay is not implemented in v0.1; unsupported streaming
  requests fail closed rather than silently degrading.
- Upstream HTTP servers must accept JSON-RPC POST requests.
- Tool definitions are refreshed on `tools/list` and before an unrecognized
  `tools/call`.
- Stdio identity comes from trusted local configuration, never from the
  untrusted JSON-RPC message.

These limits are explicit so protocol fidelity can be expanded without
weakening authorization.
