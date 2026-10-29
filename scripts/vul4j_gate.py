"""A4: real-world gate for TriageMate scorers.

Compares a scorer against the Semgrep-severity heuristic on pooled Vul4J
findings. Passes only when the scorer clears the minimum AUC margin and does
not lose precision at 90% recall, on enough entries.

Usage:
  python scripts/vul4j_gate.py
  python scripts/vul4j_gate.py --pred decision=data/vul4j-eval/decision.jsonl
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import numpy as np
from sklearn.metrics import roc_auc_score

from triage.metrics import labels, precision_at_recall

LABELS = ROOT / "data" / "vul4j-eval" / "scan-labeled.jsonl"
OUT = ROOT / "data" / "vul4j-eval" / "gate-report.json"


def read(path):
    return [json.loads(line) for line in open(path, encoding="utf-8")]


def load_pred(name, path, rows):
    by_id = {r["id"]: r for r in read(path)}
    missing = [r["id"] for r in rows if r["id"] not in by_id]
    if missing:
        sys.exit(f"{name}: {len(missing)}/{len(rows)} labels have no prediction "
                 f"(first: {missing[0]})")
    return np.array([float(by_id[r["id"]]["p_tp"]) for r in rows])


def evaluate(rows, score):
    y = labels(rows)
    auc = float(roc_auc_score(y, score)) if len(set(y)) > 1 else float("nan")
    p90, _ = precision_at_recall(y, score, 0.9)
    return {
        "n": len(y),
        "entries": len({r["vul_id"] for r in rows}),
        "positives": int(y.sum()),
        "base_precision": round(float(y.mean()), 4),
        "roc_auc": round(auc, 4),
        "precision_at_90_recall": round(float(p90), 4),
    }


def natural(key):
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", key)]


def per_entry(rows, score):
    out = {}
    for vid in sorted({r["vul_id"] for r in rows}, key=natural):
        idx = [i for i, r in enumerate(rows) if r["vul_id"] == vid]
        y = labels([rows[i] for i in idx])
        s = score[idx]
        auc = float(roc_auc_score(y, s)) if len(set(y)) > 1 else None
        out[vid] = {
            "n": len(idx),
            "positives": int(y.sum()),
            "roc_auc": round(auc, 4) if auc is not None else None,
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default=str(LABELS))
    ap.add_argument("--pred", action="append", default=[],
                    help="name=path to predictions.jsonl (id, p_tp)")
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--min-entries", type=int, default=8)
    ap.add_argument("--min-margin", type=float, default=0.02)
    args = ap.parse_args()

    rows = read(args.labels)
    if not rows:
        sys.exit(f"no rows in {args.labels}")

    scorers = {"heuristic": np.array([float(r["p_tp"]) for r in rows])}
    for spec in args.pred:
        if "=" not in spec:
            sys.exit(f"bad --pred {spec!r}, expected name=path")
        name, path = spec.split("=", 1)
        scorers[name] = load_pred(name, path, rows)

    results = {name: evaluate(rows, score) for name, score in scorers.items()}
    base = results["heuristic"]
    report = {"labels": args.labels, "scores": results,
              "per_entry": per_entry(rows, scorers["heuristic"]),
              "gate": {"min_entries": args.min_entries, "min_auc_margin": args.min_margin,
                       "baseline": "heuristic", "verdicts": {}}}

    for name, res in results.items():
        if name == "heuristic":
            continue
        auc = res["roc_auc"]
        p90 = res["precision_at_90_recall"]
        checks = {
            "entries": res["entries"] >= args.min_entries,
            "auc_margin": bool(auc >= base["roc_auc"] + args.min_margin),
            "precision_at_90_recall": bool(p90 >= base["precision_at_90_recall"]),
        }
        report["gate"]["verdicts"][name] = {"pass": all(checks.values()),
                                           "checks": checks}

    print(f"{len(rows)} findings from {base['entries']} entries "
          f"({base['positives']} TP)")
    print(f"{'scorer':<12} {'n':>4} {'AUC':>7} {'P@90R':>7} {'dAUC':>7}")
    for name, res in results.items():
        delta = res["roc_auc"] - base["roc_auc"]
        print(f"{name:<12} {res['n']:>4} {res['roc_auc']:>7.4f} "
              f"{res['precision_at_90_recall']:>7.4f} {delta:>+7.4f}")
    for name, verdict in report["gate"]["verdicts"].items():
        print(f"gate {name}: {'PASS' if verdict['pass'] else 'FAIL'} {verdict['checks']}")

    Path(args.out).write_text(json.dumps(report, indent=2) + "\n")
    print(f"report: {args.out}")


if __name__ == "__main__":
    main()
