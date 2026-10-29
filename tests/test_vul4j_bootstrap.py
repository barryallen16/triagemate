"""Tests for scripts/vul4j_bootstrap.py."""
import importlib.util
from pathlib import Path

import numpy as np

SPEC = importlib.util.spec_from_file_location(
    "vul4j_bootstrap", Path(__file__).resolve().parent.parent / "scripts"
    / "vul4j_bootstrap.py")
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


def test_perfect_separation_has_no_uncertainty():
    y = np.array([1, 1, 0, 0])
    base = np.array([0.5, 0.5, 0.6, 0.6])   # AUC 0: negatives score higher
    score = np.array([0.9, 0.8, 0.2, 0.1])  # AUC 1
    for groups in (None, np.array(["a", "a", "b", "b"])):
        out = bootstrap.interval(y, base, score, groups=groups, n=50, seed=0)
        assert out["low"] == 1.0
        assert out["high"] == 1.0
        assert out["p_nonpositive"] == 0.0
