# Threat model

## Protected assets

- Upstream tools, credentials, files, databases, messaging systems, and APIs.
- Agent and user identity.
- Tool definitions and policy configuration.
- Approval decisions and audit evidence.
- Data returned by tools.

## Trust boundaries

The agent, every MCP server, tool metadata, tool arguments, resources, prompts,
and tool results are untrusted. PostgreSQL, Redis, configured identity
providers, and the deployment administrator are trusted but may fail.

## Primary threats and controls

- Prompt injection and intent drift: least privilege, approvals, result
  labeling/scanning, and complete auditing.
- Tool poisoning/rug pulls: canonical definition hashes and quarantine.
- Excessive agency: per-principal tool and argument rules.
- Confused deputy/token passthrough: audience validation and separate upstream
  credentials.
- SSRF: URL scheme, host, and private-address restrictions.
- Path traversal: resolved-path containment checks.
- Replay: expiring, principal-bound, single-use approvals.
- Session/handle hijacking: random handles bound to verified identity.
- Resource exhaustion: message limits, deadlines, rate and concurrency limits.
- Audit leakage: field redaction, no raw bearer tokens, bounded result samples.

## Non-goals

The gateway cannot prove arbitrary natural language is free of prompt
injection. It cannot make an over-privileged upstream credential safe, and it
cannot reverse an already executed tool action. Deployments must also sandbox
local MCP servers and restrict their network and filesystem access.
