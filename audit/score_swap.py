"""Score the swap-window control against the unswapped criteria run.

Reads the two prediction files, keeps the four label definitions, and reports
AUC, precision at 90 percent recall and weighted within-rule AUC for the
identity run and both swap variants. The swap plan lives in swap_plan.json.

Usage: uv run --with numpy python score_swap.py
"""
import json
import os
import sys
from pathlib import Path

import numpy as np

import baselines as B
import sensitivity as S

AUDIT = Path(os.environ.get("AUDIT_DIR", str(Path(__file__).resolve().parent)))


def read(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def main():
    rows = S.read(f"{S.ROOT}/data/ghsa-eval/labels.jsonl")
    relabel = {r["id"]: r for r in json.loads(
        (AUDIT / "relabel.json").read_text(encoding="utf-8"))}
    strict = np.array([S.family(r["cwe"]) in {S.family(c) for c in r.get("finding_cwes", [])}
                       for r in rows])
    hunk = np.array([relabel[r["id"]]["hunk_tp"] for r in rows])
    stored = np.array([r["label"] == "TP" for r in rows])
    defs = {"L0 location proxy": stored, "L1 hunk only": hunk,
            "L2 stored + CWE": stored & strict, "L3 hunk + CWE": hunk & strict}
    ent = np.array([r["vul_id"] for r in rows])
    rules = np.array([r["rule"].split(".")[-1] for r in rows])

    ident = {r["id"]: float(r["p_tp"]) for r in
             read(AUDIT / "d1_criteria_predictions.jsonl")}
    swap = {}
    for r in read(AUDIT / "d1_swap_predictions.jsonl"):
        swap.setdefault(r["variant"], {})[r["id"]] = float(r["p_tp"])
    missing = [r["id"] for r in rows if r["id"] not in ident or
               any(r["id"] not in v for v in swap.values())]
    if missing:
        sys.exit(f"{len(missing)} rows missing from predictions")
    scores = {"identity": np.array([ident[r["id"]] for r in rows])}
    for variant, by in swap.items():
        scores[variant] = np.array([by[r["id"]] for r in rows])

    out = {}
    for dname, y in defs.items():
        y = y.astype(int)
        out[dname] = {}
        print(f"\n{dname}: {int(y.sum())} TP")
        for name, s in scores.items():
            w = B.weighted_within_rule(y, s, rules)
            boot = S.bootstrap_delta(y, s, scores["identity"], ent)
            row = {"auc": round(float(S.auc(y, s)), 4),
                   "p_at_90r": round(float(S.p_at_r(y, s)[0]), 4),
                   "within_rule": round(float(w), 4),
                   "identity_minus_this": boot}
            out[dname][name] = row
            print(f"  {name:<9} AUC {row['auc']:.4f}  P@90R {row['p_at_90r']:.4f}  "
                  f"within-rule {row['within_rule']:.4f}  "
                  f"identity-minus-this CI [{boot['low']:+.3f},{boot['high']:+.3f}]")
    (AUDIT / "score-swap.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nwrote {AUDIT / 'score-swap.json'}")


if __name__ == "__main__":
    main()
