"""Independent recompute of every published second-set number.

Deliberately does not import triage, scripts, or sklearn. Rank-based AUC,
the documented whole-tie precision-at-recall rule, and the bootstrap are
re-implemented here so a shared bug cannot hide.
"""
import json
import os
from pathlib import Path
import sys

import numpy as np

ROOT = Path(os.environ.get("TRIAGEMATE_ROOT", str(Path(__file__).resolve().parent.parent)))
AUDIT = Path(os.environ.get("AUDIT_DIR", str(Path(__file__).resolve().parent)))


def read(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def y_of(rows):
    return np.array([1 if r["label"] == "TP" else 0 for r in rows], dtype=int)


def auc(y, s):
    """Rank AUC with average ranks for ties."""
    s = np.asarray(s, float)
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s), float)
    sorted_s = s[order]
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and sorted_s[j + 1] == sorted_s[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    pos = y == 1
    n_pos, n_neg = pos.sum(), (~pos).sum()
    if not n_pos or not n_neg:
        return float("nan")
    return (ranks[pos].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def p_at_r(y, s, target=0.9):
    """Precision at the highest threshold that keeps target recall, ties whole."""
    s = np.asarray(s, float)
    positives = y.sum()
    if not positives:
        return 0.0, 0.0
    for threshold in sorted(set(s.tolist()), reverse=True):
        accepted = s >= threshold
        tp = int(y[accepted].sum())
        recall = tp / positives
        if recall >= target:
            return tp / int(accepted.sum()), recall
    return 0.0, 0.0


def delta(y, base, score, idx):
    y = y[idx]
    if y.min() == y.max():
        return None
    return auc(y, score[idx]) - auc(y, base[idx])


def bootstrap(y, base, score, groups, n=2000, seed=0):
    rng = np.random.default_rng(seed)
    out = []
    if groups is None:
        for _ in range(n):
            idx = rng.integers(0, len(y), len(y))
            d = delta(y, base, score, idx)
            if d is not None:
                out.append(d)
    else:
        uniq = list(dict.fromkeys(groups.tolist()))
        members = [np.where(groups == g)[0] for g in uniq]
        for _ in range(n):
            idx = np.concatenate([members[i] for i in rng.integers(0, len(uniq), len(uniq))])
            d = delta(y, base, score, idx)
            if d is not None:
                out.append(d)
    v = np.array(out)
    return {"n": len(v), "low": round(float(np.percentile(v, 2.5)), 4),
            "high": round(float(np.percentile(v, 97.5)), 4),
            "p_nonpositive": round(float((v <= 0).mean()), 4)}


def load_pred(path, rows):
    by_id = {r["id"]: float(r["p_tp"]) for r in read(path)}
    missing = [r["id"] for r in rows if r["id"] not in by_id]
    if missing:
        sys.exit(f"{path}: {len(missing)} missing predictions")
    return np.array([by_id[r["id"]] for r in rows])


def loo_min(y, base, score, groups):
    vals = []
    for g in sorted(set(groups.tolist())):
        idx = np.where(groups != g)[0]
        d = delta(y, base, score, idx)
        if d is not None:
            vals.append(d)
    return round(min(vals), 4)


def run(name, labels, preds):
    rows = read(labels)
    y = y_of(rows)
    base = np.array([float(r["p_tp"]) for r in rows])
    entries = np.array([r["vul_id"] for r in rows])
    print(f"\n=== {name}: {len(rows)} rows, {len(set(entries))} entries, {int(y.sum())} TP")
    print(f"heuristic  AUC {auc(y, base):.4f}  P@90R {p_at_r(y, base)[0]:.4f}")
    result = {"rows": len(rows), "entries": int(len(set(entries))),
              "positives": int(y.sum()),
              "heuristic": {"auc": round(auc(y, base), 4),
                            "p_at_90r": round(p_at_r(y, base)[0], 4)},
              "scorers": {}}
    for sname, path in preds:
        s = load_pred(path, rows)
        d = auc(y, s) - auc(y, base)
        print(f"{sname:<10} AUC {auc(y, s):.4f}  P@90R {p_at_r(y, s)[0]:.4f}  "
              f"dAUC {d:+.4f}  within-rule pending")
        result["scorers"][sname] = {
            "auc": round(auc(y, s), 4), "p_at_90r": round(p_at_r(y, s)[0], 4),
            "delta_auc": round(d, 4),
            "row_bootstrap": bootstrap(y, base, s, None),
            "entry_bootstrap": bootstrap(y, base, s, entries),
            "loo_min": loo_min(y, base, s, entries),
        }
    return result


def main():
    out = {}
    out["vul4j"] = run(
        "vul4j",
        str(ROOT / "data/vul4j-eval/scan-labeled.jsonl"),
        [("d1", str(ROOT / "data/vul4j-eval/d1_predictions.jsonl")),
         ("kev", str(ROOT / "data/vul4j-eval/kev_predictions.jsonl"))])
    out["ghsa"] = run(
        "ghsa",
        str(ROOT / "data/ghsa-eval/labels.jsonl"),
        [("d1", str(ROOT / "data/ghsa-eval/d1_predictions.jsonl")),
         ("kev", str(ROOT / "data/ghsa-eval/kev_predictions.jsonl"))])
    with open(AUDIT / "recompute.json", "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nwrote {AUDIT / 'recompute.json'}")


if __name__ == "__main__":
    main()
