from prometheus_client import Counter, Histogram

REQUESTS = Counter(
    "mcp_gateway_requests_total",
    "Gateway requests by method and decision.",
    ("method", "decision"),
)
LATENCY = Histogram(
    "mcp_gateway_request_duration_seconds",
    "End-to-end gateway request latency.",
    ("method",),
)
POLICY_LATENCY = Histogram(
    "mcp_gateway_policy_duration_seconds",
    "Policy evaluation latency.",
)
RESULT_FLAGS = Counter(
    "mcp_gateway_flagged_results_total",
    "Tool results flagged by defense-in-depth scanning.",
    ("server_id", "tool_name"),
)
