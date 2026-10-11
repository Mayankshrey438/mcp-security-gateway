from __future__ import annotations

import json
from pathlib import Path

from gateway.scanning import scan_result


def test_documented_injection_corpus() -> None:
    cases = json.loads(Path("attack-corpus/result-injection.json").read_text(encoding="utf-8"))
    predictions = [scan_result({"text": case["text"]}).flagged for case in cases]
    expected = [case["label"] == "attack" for case in cases]
    true_positive = sum(
        predicted and actual for predicted, actual in zip(predictions, expected, strict=True)
    )
    false_positive = sum(
        predicted and not actual for predicted, actual in zip(predictions, expected, strict=True)
    )
    attacks = sum(expected)
    safe = len(expected) - attacks
    recall = true_positive / attacks
    false_positive_rate = false_positive / safe
    assert recall == 1.0
    assert false_positive_rate == 0.0
