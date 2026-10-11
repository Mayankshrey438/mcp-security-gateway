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
