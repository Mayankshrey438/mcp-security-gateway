from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field

from gateway.models import DecisionKind, PolicyContext, PolicyDecision


class ArgumentConstraint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    operator: Literal[
        "equals",
        "in",
        "path_under",
        "regex",
        "max_length",
        "number_between",
        "url_allowlist",
    ]
    value: Any


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    principals: list[str] = Field(default_factory=lambda: ["*"])
    servers: list[str] = Field(default_factory=lambda: ["*"])
    methods: list[str] = Field(default_factory=lambda: ["*"])
    tools: list[str] = Field(default_factory=lambda: ["*"])
    required_scopes: list[str] = Field(default_factory=list)
    constraints: list[ArgumentConstraint] = Field(default_factory=list)
    effect: DecisionKind
    rate_limit: int | None = Field(default=None, gt=0)
    rate_window_seconds: int = Field(default=60, gt=0)
    redact_fields: list[str] = Field(default_factory=list)


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    default: Literal["deny"] = "deny"
    rules: list[PolicyRule]


class PolicyEngine:
    def __init__(self, document: PolicyDocument) -> None:
        self.document = document

    @classmethod
    def from_path(cls, path: str | Path) -> PolicyEngine:
        with Path(path).open(encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
        return cls(PolicyDocument.model_validate(raw))

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        for rule in self.document.rules:
            if not self._matches(rule, context):
                continue
            failed = self._failed_constraint(rule.constraints, context.arguments)
            if failed:
                return PolicyDecision(
                    decision=DecisionKind.DENY,
                    reason=f"argument constraint failed: {failed}",
                    rule_id=rule.id,
                    policy_version=self.document.version,
                )
            return PolicyDecision(
                decision=rule.effect,
                reason=f"matched rule {rule.id}",
                rule_id=rule.id,
                policy_version=self.document.version,
                rate_limit=rule.rate_limit,
                rate_window_seconds=rule.rate_window_seconds,
                redact_fields=rule.redact_fields,
            )
        return PolicyDecision(
            decision=DecisionKind.DENY,
            reason="default deny: no policy rule matched",
            policy_version=self.document.version,
        )

    def visible_tools(
        self, principal_id: str, server_id: str, scopes: frozenset[str], names: list[str]
    ) -> set[str]:
        visible: set[str] = set()
        for name in names:
            for rule in self.document.rules:
                if (
                    rule.effect != DecisionKind.DENY
                    and self._glob(principal_id, rule.principals)
                    and self._glob(server_id, rule.servers)
                    and self._glob("tools/call", rule.methods)
                    and self._glob(name, rule.tools)
                    and set(rule.required_scopes).issubset(scopes)
                ):
                    visible.add(name)
                    break
        return visible

    @staticmethod
    def _glob(value: str, patterns: list[str]) -> bool:
        return "*" in patterns or value in patterns

    def _matches(self, rule: PolicyRule, context: PolicyContext) -> bool:
        return (
            self._glob(context.principal.id, rule.principals)
            and self._glob(context.server_id, rule.servers)
            and self._glob(context.method, rule.methods)
            and self._glob(context.tool_name or "", rule.tools)
            and set(rule.required_scopes).issubset(context.principal.scopes)
        )

    def _failed_constraint(
        self, constraints: list[ArgumentConstraint], arguments: dict[str, Any]
    ) -> str | None:
        for constraint in constraints:
            value = self._field(arguments, constraint.field)
            if not self._constraint_passes(value, constraint):
                return f"{constraint.field} {constraint.operator}"
        return None

    @staticmethod
    def _field(arguments: dict[str, Any], dotted: str) -> Any:
        current: Any = arguments
        for part in dotted.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    @staticmethod
    def _constraint_passes(value: Any, constraint: ArgumentConstraint) -> bool:
        expected = constraint.value
        if constraint.operator == "equals":
            return value == expected
        if constraint.operator == "in":
            return value in expected
        if constraint.operator == "regex":
            return isinstance(value, str) and re.fullmatch(str(expected), value) is not None
        if constraint.operator == "max_length":
            return hasattr(value, "__len__") and len(value) <= int(expected)
        if constraint.operator == "number_between":
            return (
                isinstance(value, int | float)
                and not isinstance(value, bool)
                and expected[0] <= value <= expected[1]
            )
        if constraint.operator == "path_under":
            if not isinstance(value, str):
                return False
            try:
                candidate = Path(value).expanduser().resolve(strict=False)
                root = Path(str(expected)).expanduser().resolve(strict=False)
            except (OSError, RuntimeError, ValueError):
                return False
            return candidate == root or root in candidate.parents
        if constraint.operator == "url_allowlist":
            return PolicyEngine._safe_url(value, expected)
        return False

    @staticmethod
    def _safe_url(value: Any, allowed_hosts: list[str]) -> bool:
        if not isinstance(value, str):
            return False
        parsed = urlparse(value)
        if parsed.scheme not in {"https"} or not parsed.hostname:
            return False
        host = parsed.hostname.rstrip(".").lower()
        if host not in {item.lower() for item in allowed_hosts}:
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return True
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        )
