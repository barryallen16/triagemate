"""Bootstrap intervals for the gate's ROC-AUC delta.

The gate ranks scorers on a few dozen alerts from a few entries, so the point
estimate is noisy. This resamples rows, or whole entries, and reports the 95%
interval for the scorer-minus-heuristic AUC and the share of resamples where
the scorer does not beat the heuristic.

Usage:
  python scripts/vul4j_bootstrap.py --pred d1=data/vul4j-eval/d1_predictions.jsonl
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from triage.metrics import labels


def read(path):
    return [json.loads(line) for line in open(path, encoding="utf-8")]


def load_pred(path, rows):
    by_id = {r["id"]: r for r in read(path)}
    missing = [r["id"] for r in rows if r["id"] not in by_id]
    if missing:
        sys.exit(f"{path}: {len(missing)} labels have no prediction")
    return np.array([float(by_id[r["id"]]["p_tp"]) for r in rows])


def auc_delta(y, base, score, idx):
    y = y[idx]
    if y.min() == y.max():
        return None
    return float(roc_auc_score(y, score[idx]) - roc_auc_score(y, base[idx]))


def interval(y, base, score, groups=None, n=2000, seed=0):
    rng = np.random.default_rng(seed)
    deltas = []
    if groups is None:
        for _ in range(n):
            idx = rng.integers(0, len(y), len(y))
            delta = auc_delta(y, base, score, idx)
            if delta is not None:
                deltas.append(delta)
    else:
        uniq = list(dict.fromkeys(groups))
        members = [np.where(groups == g)[0] for g in uniq]
        for _ in range(n):
            idx = np.concatenate([members[i] for i in
                                  rng.integers(0, len(uniq), len(uniq))])
            delta = auc_delta(y, base, score, idx)
            if delta is not None:
                deltas.append(delta)
    if not deltas:
        return {"n": 0, "low": None, "high": None, "p_nonpositive": None}
    values = np.array(deltas)
    return {
        "n": len(values),
        "low": round(float(np.percentile(values, 2.5)), 4),
        "high": round(float(np.percentile(values, 97.5)), 4),
        "p_nonpositive": round(float((values <= 0).mean()), 4),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default=str(ROOT / "data" / "vul4j-eval"
                                            / "scan-labeled.jsonl"))
    ap.add_argument("--pred", action="append", default=[],
                    help="name=path, with p_tp per label id")
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    rows = read(args.labels)
    y = labels(rows)
    base = np.array([float(r["p_tp"]) for r in rows])
    entries = np.array([r["vul_id"] for r in rows])
    report = {"labels": args.labels, "rows": len(rows),
              "entries": int(len(set(entries))), "scores": {}}
    for spec in args.pred:
        if "=" not in spec:
            sys.exit(f"bad --pred {spec!r}, expected name=path")
        name, path = spec.split("=", 1)
        score = load_pred(path, rows)
        point = auc_delta(y, base, score, np.arange(len(y)))
        report["scores"][name] = {
            "delta": None if point is None else round(point, 4),
            "row": interval(y, base, score, n=args.n, seed=args.seed),
            "entry": interval(y, base, score, groups=entries,
                              n=args.n, seed=args.seed),
        }
    print(json.dumps(report, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
