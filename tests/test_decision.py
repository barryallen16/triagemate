"""Tests for triage/decision.py: decision state, options and confidence."""
import pytest

from triage.cli import main
from triage.decision import (
    OPTIONS, QUESTION, confidence_of, decision_input, option_token_ids,
    prompt_of, state_of,
)


class FakeTokenizer:
    """Maps ' TP' and ' FP' to one token, and anything else to two."""

    def __init__(self, split=False):
        self.split = split

    def __call__(self, text, add_special_tokens=False):
        if not self.split and text in (" TP", " FP"):
            ids = [1 if text == " TP" else 2]
        elif text in (" TP", " FP"):
            ids = [1, 1]
        else:
            ids = [7, 7]
        return type("Encoded", (), {"input_ids": ids})()


ROW = {
    "id": "VUL4J-45:rule.x:path/XsltRenderer.java:91",
    "rule": "java.lang.security.audit.unsafe-reflection",
    "cwe": "CWE-74",
    "file": "/tmp/checkout/src/XsltRenderer.java",
    "line": 91,
    "severity": "ERROR",
    "message": "Reflected input reaches a transformer.",
    "code_window": "public void render(String xsl) {\n    transform(xsl);\n}\n",
}


def test_state_carries_every_decision_input():
    state = state_of(ROW)
    assert "java.lang.security.audit.unsafe-reflection" in state
    assert "CWE-74" in state
    assert "Severity: ERROR" in state
    assert "XsltRenderer.java" in state
    assert "Line: 91" in state
    assert "Reflected input reaches a transformer." in state
    assert "transform(xsl)" in state


def test_state_uses_basename_not_absolute_path():
    assert "/tmp/checkout" not in state_of(ROW)


def test_state_truncates_long_windows():
    row = dict(ROW, code_window="x" * 40000)
    state = state_of(row)
    assert len(state) < 40000
    assert "truncated" in state


def test_decision_input_follows_semif_shape():
    decision = decision_input(ROW)
    assert set(decision) == {"id", "state", "question", "options"}
    assert decision["id"] == ROW["id"]
    assert decision["question"] == QUESTION
    assert [o["id"] for o in decision["options"]] == ["TP", "FP"]
    for option in decision["options"]:
        assert option["description"]


def test_row_without_id_is_allowed():
    row = {k: v for k, v in ROW.items() if k != "id"}
    assert decision_input(row)["id"] == ""


def test_prompt_lists_the_options():
    prompt = prompt_of(ROW)
    assert QUESTION in prompt
    assert "- TP:" in prompt
    assert "- FP:" in prompt
    assert "exactly one option id" in prompt


def test_confidence_is_distance_from_the_tie():
    assert confidence_of(0.5) == 0.5
    assert confidence_of(0.9) == pytest.approx(0.9)
    assert confidence_of(0.05) == pytest.approx(0.95)
    assert confidence_of(1.0) == pytest.approx(1.0)


def test_cli_accepts_the_decision_scorer():
    # Parsing must accept "decision" before any model is loaded.
    with pytest.raises(SystemExit) as excinfo:
        main(["/no/such/path", "--scorer", "decision"])
    assert "no such path" in str(excinfo.value)


def test_option_tokens_are_single_ids():
    assert option_token_ids(FakeTokenizer()) == [1, 2]


def test_multi_token_option_is_rejected():
    with pytest.raises(ValueError, match="tokenizes to 2 tokens"):
        option_token_ids(FakeTokenizer(split=True))
