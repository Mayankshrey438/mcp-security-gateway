from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from gateway.models import DecisionKind, PolicyContext, Principal
from gateway.policy import PolicyDocument, PolicyEngine
from gateway.security import stable_hash


def engine() -> PolicyEngine:
    return PolicyEngine(
        PolicyDocument.model_validate(
            {
                "version": "property-test",
                "rules": [
                    {
                        "id": "docs-only",
                        "principals": ["research-agent"],
                        "servers": ["filesystem"],
                        "methods": ["tools/call"],
                        "tools": ["read_file"],
                        "constraints": [
                            {"field": "path", "operator": "path_under", "value": "/docs"}
                        ],
                        "effect": "allow",
                    }
                ],
            }
        )
    )


@given(st.text(min_size=1).filter(lambda value: not value.startswith("/docs")))
def test_paths_outside_docs_are_never_allowed(path: str) -> None:
    decision = engine().evaluate(
        PolicyContext(
            principal=Principal(id="research-agent"),
            server_id="filesystem",
            method="tools/call",
            tool_name="read_file",
            arguments={"path": path},
            transport="http",
            correlation_id="property",
        )
    )
    assert decision.decision == DecisionKind.DENY


@given(st.dictionaries(st.text(min_size=1), st.integers(), max_size=10))
def test_canonical_argument_hash_ignores_mapping_order(arguments: dict[str, int]) -> None:
    assert stable_hash(arguments) == stable_hash(dict(reversed(list(arguments.items()))))
