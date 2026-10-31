"""Tests for triage/cli.py - heuristic scorer and output parsing."""
from triage.cli import heuristic_score


def test_heuristic_score_returns_valid_probability():
    row = {"severity": "ERROR", "message": "some warning"}
    p, text = heuristic_score(row)
    assert 0.0 <= p <= 1.0
    assert text == ""


def test_heuristic_score_info():
    row = {"severity": "INFO", "message": ""}
    p, _ = heuristic_score(row)
    assert p == 0.25  # INFO severity = 1 / 4


def test_heuristic_score_unknown_severity():
    row = {"severity": "NOTICE", "message": ""}
    p, _ = heuristic_score(row)
    assert p == 0.5  # default WARNING = 2 / 4
