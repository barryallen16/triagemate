"""Tests for triage/metrics.py — hand-computed expectations."""
import numpy as np

from triage.metrics import precision_at_recall, ece, summarize


def test_precision_at_recall_basic():
    # Scores descending, all positives first: at 90% recall we keep 9 of 10.
    y = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0])
    score = np.linspace(0.95, 0.05, 15)
    p, r = precision_at_recall(y, score, 0.9)
    assert p == 1.0
    assert r == 0.9


def test_precision_at_recall_mixed():
    y = np.array([1, 0, 1, 0, 1, 0, 1, 0, 1, 0])
    score = np.linspace(0.9, 0.1, 10)
    # sorted by score desc: y = [1,0,1,0,1,0,1,0,1,0]
    # 5 positives total; first threshold reaching 90% recall keeps 9 of 10
    # (recall jumps 0.8 -> 1.0), so precision = 5/9, recall = 1.0
    p, r = precision_at_recall(y, score, 0.9)
    assert p == 5 / 9
    assert r == 1.0


def test_precision_at_recall_unreachable():
    # Only 1 positive out of 100; target 90% recall requires keeping 90%,
    # but there aren't enough positives — actually recall can still reach
    # 0.9 if we keep all. With y.sum()=1, recall hits 1.0 at the positive.
    y = np.array([0, 0, 0, 1, 0])
    score = np.array([0.1, 0.2, 0.3, 0.9, 0.4])
    p, r = precision_at_recall(y, score, 0.9)
    # sorted desc: y=[1,0,0,0,0], recall hits 1.0 at index 0
    assert p == 1.0
    assert r == 1.0


def test_precision_at_recall_groups_ties():
    # Both positives tie with both negatives: a threshold must accept all four.
    y = np.array([1, 1, 0, 0])
    score = np.array([0.75, 0.75, 0.75, 0.75])
    p, r = precision_at_recall(y, score, 0.9)
    assert p == 0.5
    assert r == 1.0


def test_ece_perfect_calibration():
    # Confs exactly match labels within each bin -> ECE = 0.
    y = np.array([0.0, 0.0, 1.0, 1.0])
    score = np.array([0.0, 0.0, 1.0, 1.0])
    assert ece(y, score, bins=2) == 0.0


def test_ece_poor_calibration():
    y = np.array([0.0, 0.0, 0.0, 0.0])
    score = np.array([0.9, 0.9, 0.9, 0.9])
    # all in bin 0.8-1.0, mean conf 0.9, accuracy 0.0 -> ECE = 0.9
    assert ece(y, score, bins=10) == 0.9


def test_summarize_basic():
    y = np.array([1, 1, 0, 0])
    score = np.array([0.9, 0.8, 0.3, 0.2])
    out = summarize(y, score, "m")
    assert out["precision"] == 1.0
    assert out["recall"] == 1.0
    assert out["f1"] == 1.0
    assert out["tp"] == 2
    assert out["fp"] == 0
    assert out["fn"] == 0


def test_summarize_all_negatives():
    y = np.array([0, 0, 0])
    score = np.array([0.1, 0.2, 0.3])
    out = summarize(y, score, "m")
    assert out["precision"] == 0.0
    assert out["recall"] == 0.0
    assert out["roc_auc"] != out["roc_auc"]  # nan for single class
    assert "roc_auc" in out
