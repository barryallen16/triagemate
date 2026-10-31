"""Score an extra prediction file under L0 to L3, reusing sensitivity.py."""
import json
import sys
from pathlib import Path

import numpy as np

import sensitivity as S

ROOT = S.ROOT
AUDIT = Path(S.AUDIT)


def main(path, name):
    rows = S.read(f"{ROOT}/data/ghsa-eval/labels.jsonl")
    relabel = {r["id"]: r for r in json.loads(
        (AUDIT / "relabel.json").read_text(encoding="utf-8"))}
    by = {r["id"]: float(r["p_tp"]) for r in S.read(path)}
    missing = [r["id"] for r in rows if r["id"] not in by]
    if missing:
        sys.exit(f"{path}: {len(missing)} rows missing")
    pred = np.array([by[r["id"]] for r in rows])
    base = np.array([float(r["p_tp"]) for r in rows])
    groups = np.array([r["vul_id"] for r in rows])
    strict = np.array([S.family(r["cwe"]) in {S.family(c) for c in r.get("finding_cwes", [])}
                       for r in rows])
    hunk = np.array([relabel[r["id"]]["hunk_tp"] for r in rows])
    stored = np.array([r["label"] == "TP" for r in rows])
    defs = {"L0 location proxy": stored, "L1 hunk only": hunk,
            "L2 stored + CWE": stored & strict, "L3 hunk + CWE": hunk & strict}
    out = {}
    for dname, y in defs.items():
        y = y.astype(int)
        row = {"positives": int(y.sum()),
               "heuristic": {"auc": round(S.auc(y, base), 4),
                             "p_at_90r": round(S.p_at_r(y, base)[0], 4)},
               "pred": {"auc": round(S.auc(y, pred), 4),
                        "p_at_90r": round(S.p_at_r(y, pred)[0], 4),
                        "delta_auc": round(S.auc(y, pred) - S.auc(y, base), 4),
                        "entry_bootstrap": S.bootstrap_delta(y, base, pred, groups)}}
        row["gate_pass"] = bool(
            row["pred"]["auc"] >= row["heuristic"]["auc"] + 0.02
            and row["pred"]["p_at_90r"] >= row["heuristic"]["p_at_90r"])
        out[dname] = row
        print(f"{dname}: {int(y.sum())} TP  heuristic {row['heuristic']['auc']:.4f}/"
              f"{row['heuristic']['p_at_90r']:.4f}  {name} "
              f"{row['pred']['auc']:.4f}/{row['pred']['p_at_90r']:.4f}  "
              f"dAUC {row['pred']['delta_auc']:+.4f}  "
              f"CI [{row['pred']['entry_bootstrap']['low']:+.3f},"
              f"{row['pred']['entry_bootstrap']['high']:+.3f}]  "
              f"{'PASS' if row['gate_pass'] else 'FAIL'}")
    outpath = AUDIT / f"score-{name}.json"
    outpath.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {outpath}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python score_pred.py name=path")
    n, p = sys.argv[1].split("=", 1)
    main(p, n)
