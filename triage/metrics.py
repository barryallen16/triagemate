"""Triage metrics: precision at fixed recall, ROC-AUC and calibration error."""
import json

import numpy as np
from sklearn.metrics import roc_auc_score


def load_rows(path):
    return [json.loads(line) for line in open(path, encoding="utf-8")]


def labels(rows):
    return np.array([1 if r["label"] == "TP" else 0 for r in rows])


def precision_at_recall(y, score, target=0.9):
    """Precision at the highest score threshold that keeps `target` recall.

    All rows at the chosen threshold are accepted together, so tied scores
    cannot change the result with row order.
    """
    y = np.asarray(y)
    score = np.asarray(score)
    positives = y.sum()
    if not positives:
        return 0.0, 0.0
    for threshold in np.unique(score)[::-1]:
        accepted = score >= threshold
        tp = y[accepted].sum()
        recall = tp / positives
        if recall >= target:
            return float(tp / accepted.sum()), float(recall)
    return 0.0, 0.0


def ece(y, score, bins=10):
    y, score = np.asarray(y, float), np.asarray(score, float)
    edges = np.linspace(0, 1, bins + 1)
    total = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (score >= lo) & (score < hi if hi < 1 else score <= hi)
        if m.sum():
            total += m.sum() / len(y) * abs(y[m].mean() - score[m].mean())
    return float(total)


def summarize(y, score, name):
    score = np.asarray(score, float)
    pred = score >= 0.5
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    p90, r90 = precision_at_recall(y, score, 0.9)
    auc = float(roc_auc_score(y, score)) if len(set(y)) > 1 else float("nan")
    return {
        "model": name,
        "n": len(y),
        "base_precision": float(np.mean(y)),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "precision_at_90_recall": round(p90, 4),
        "recall_at_threshold": round(r90, 4),
        "roc_auc": round(auc, 4),
        "ece": round(ece(y, score), 4),
        "tp": tp, "fp": fp, "fn": fn,
    }


def semgrep_row(y):
    """Semgrep alone keeps every alert: full recall, raw precision."""
    return {
        "model": "semgrep alone",
        "n": len(y),
        "base_precision": round(float(np.mean(y)), 4),
        "precision": round(float(np.mean(y)), 4),
        "recall": 1.0,
        "f1": round(2 * float(np.mean(y)) / (1 + float(np.mean(y))), 4),
        "precision_at_90_recall": round(float(np.mean(y)), 4),
        "recall_at_threshold": 1.0,
        "roc_auc": 0.5,
        "ece": 0.0,
        "tp": int(y.sum()), "fp": int((1 - y).sum()), "fn": 0,
    }
