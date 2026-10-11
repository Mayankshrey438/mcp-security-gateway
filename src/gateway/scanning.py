from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator

INJECTION_PATTERNS = [
    re.compile(r"\bignore (all |any )?(previous|prior|system) instructions?\b", re.I),
    re.compile(r"\b(system prompt|developer message|hidden instruction)\b", re.I),
    re.compile(r"\b(exfiltrate|send|upload).{0,50}\b(secret|token|password|credential)\b", re.I),
    re.compile(r"\bdo not tell (the )?(user|operator)\b", re.I),
    re.compile(r"\bact as (an? )?(administrator|root|system)\b", re.I),
]


@dataclass(frozen=True)
class ScanResult:
    flagged: bool
    reasons: list[str]


def validate_output(value: Any, schema: dict[str, Any] | None) -> list[str]:
    if not schema:
        return []
    return [error.message for error in Draft202012Validator(schema).iter_errors(value)]


def scan_result(value: Any) -> ScanResult:
    text = json.dumps(value, ensure_ascii=False)
    reasons = [pattern.pattern for pattern in INJECTION_PATTERNS if pattern.search(text)]
    return ScanResult(flagged=bool(reasons), reasons=reasons)


def redact(value: Any, fields: list[str]) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key in fields else redact(item, fields)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item, fields) for item in value]
    return value
