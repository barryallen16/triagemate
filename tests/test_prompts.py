"""Tests for triage/prompts.py - verdict/why/fix parsing."""
from triage.prompts import parse, target


def test_parse_full():
    text = "VERDICT: TP\nWHY: The sink is reached.\nFIX: Validate input."
    out = parse(text)
    assert out["verdict"] == "TP"
    assert out["why"] == "The sink is reached."
    assert out["fix"] == "Validate input."


def test_parse_missing_why_fix():
    text = "VERDICT: FP"
    out = parse(text)
    assert out["verdict"] == "FP"
    assert out["why"] == ""
    assert out["fix"] == ""


def test_parse_empty():
    out = parse("")
    assert out["verdict"] is None
    assert out["why"] == ""
    assert out["fix"] == ""


def test_target_roundtrip():
    row = {"label": "TP", "reason": "reason text", "fix": "fix text"}
    out = target(row)
    assert out == "VERDICT: TP\nWHY: reason text\nFIX: fix text"
