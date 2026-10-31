"""Gate under four label definitions: location proxy, hunk-only, CWE, both.

L0 stored labels (hunk or touched method, any CWE).
L1 hunk-only (finding line inside a changed hunk, any CWE).
L2 stored labels restricted to findings whose rule CWE matches the advisory.
L3 L1 and L2 together.

Reports AUC, P@90R, the gate checks and an entry bootstrap for delta AUC.
"""
import json
import os
from pathlib import Path
import re
import sys

import numpy as np

ROOT = Path(os.environ.get("TRIAGEMATE_ROOT", str(Path(__file__).resolve().parent.parent)))
AUDIT = Path(os.environ.get("AUDIT_DIR", str(Path(__file__).resolve().parent)))


def read(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def family(cwe):
    m = re.match(r"CWE-(\d+)", cwe or "")
    return m.group(1) if m else ""


def auc(y, s):
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
    n_pos, n_neg = int(pos.sum()), int((~pos).sum())
    if not n_pos or not n_neg:
        return float("nan")
    return (ranks[pos].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def p_at_r(y, s, target=0.9):
    positives = int(y.sum())
    if not positives:
        return 0.0, 0.0
    for threshold in sorted(set(np.asarray(s, float).tolist()), reverse=True):
        accepted = np.asarray(s) >= threshold
        tp = int(y[accepted].sum())
        if tp / positives >= target:
            return tp / int(accepted.sum()), tp / positives
    return 0.0, 0.0


def bootstrap_delta(y, base, score, groups, n=2000, seed=0):
    rng = np.random.default_rng(seed)
    uniq = list(dict.fromkeys(groups.tolist()))
    members = [np.where(groups == g)[0] for g in uniq]
    out = []
    for _ in range(n):
        idx = np.concatenate([members[i] for i in rng.integers(0, len(uniq), len(uniq))])
        if y[idx].min() == y[idx].max():
            continue
        out.append(auc(y[idx], score[idx]) - auc(y[idx], base[idx]))
    v = np.array(out)
    return {"valid": len(v), "low": round(float(np.percentile(v, 2.5)), 4),
            "high": round(float(np.percentile(v, 97.5)), 4),
            "share_le_0": round(float((v <= 0).mean()), 4)}


def main():
    rows = read(f"{ROOT}/data/ghsa-eval/labels.jsonl")
    relabel = {r["id"]: r for r in json.loads(
        open(f"{AUDIT}/relabel.json", encoding="utf-8").read())}
    pool = {r["vul_id"]: r for r in read(f"{ROOT}/data/ghsa-eval/pool.jsonl")}
    pred = {}
    for name in ("d1", "kev"):
        by = {r["id"]: float(r["p_tp"]) for r in read(
            f"{ROOT}/data/ghsa-eval/{name}_predictions.jsonl")}
        pred[name] = np.array([by[r["id"]] for r in rows])
    base = np.array([float(r["p_tp"]) for r in rows])
    groups = np.array([r["vul_id"] for r in rows])
    strict = np.array([family(r["cwe"]) in {family(c) for c in r.get("finding_cwes", [])}
                       for r in rows])
    hunk = np.array([relabel[r["id"]]["hunk_tp"] for r in rows])
    stored = np.array([r["label"] == "TP" for r in rows])

    defs = {
        "L0 location proxy": stored,
        "L1 hunk only": hunk,
        "L2 stored + CWE": stored & strict,
        "L3 hunk + CWE": hunk & strict,
    }
    out = {}
    for name, y in defs.items():
        y = y.astype(int)
        entry = {"positives": int(y.sum()), "base_rate": round(float(y.mean()), 4),
                 "off_cwe_positives": int((y.astype(bool) & ~strict).sum()),
                 "method_only_positives": int((y.astype(bool) & ~hunk).sum())}
        scores = {"heuristic": base, **pred}
        vals = {}
        for sname, s in scores.items():
            vals[sname] = {
                "auc": round(auc(y, s), 4),
                "p_at_90r": round(p_at_r(y, s)[0], 4),
                "recall": round(p_at_r(y, s)[1], 4),
                "delta_auc": round(auc(y, s) - auc(y, base), 4),
            }
        for sname in ("d1", "kev"):
            v = vals[sname]
            v["entry_bootstrap"] = bootstrap_delta(y, base, scores[sname], groups)
            v["gate_pass"] = bool(
                len(set(groups)) >= 8
                and v["auc"] >= vals["heuristic"]["auc"] + 0.02
                and v["p_at_90r"] >= vals["heuristic"]["p_at_90r"])
        entry["scores"] = vals
        out[name] = entry
        print(f"\n{name}: {int(y.sum())} TP of {len(y)} "
              f"(off-CWE {entry['off_cwe_positives']}, method-only {entry['method_only_positives']})")
        for sname, v in vals.items():
            extra = ""
            if "gate_pass" in v:
                b = v["entry_bootstrap"]
                extra = (f"  dAUC CI [{b['low']:+.3f},{b['high']:+.3f}]"
                         f"  gate {'PASS' if v['gate_pass'] else 'FAIL'}")
            print(f"  {sname:<10} AUC {v['auc']:.4f}  P@90R {v['p_at_90r']:.4f} "
                  f"({v['recall']:.2f} recall)  dAUC {v['delta_auc']:+.4f}{extra}")
    with open(f"{AUDIT}/sensitivity.json", "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nwrote {AUDIT}/sensitivity.json")


if __name__ == "__main__":
    sys.exit(main())
