"""Score the targeted-sink run (identity and rule-swap) across L0-L3 and within-rule metrics.

Reuses sensitivity.py and baselines.py logic.
Usage: python score_targeted.py
"""
import json
import os
import sys
from pathlib import Path

import numpy as np

import baselines as B
import sensitivity as S

AUDIT = Path(os.environ.get("AUDIT_DIR", str(Path(__file__).resolve().parent)))
ROOT = Path(os.environ.get("TRIAGEMATE_ROOT", str(AUDIT.parent)))


def read(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def main(ident_path=None, swap_path=None):
    if ident_path is None:
        ident_path = AUDIT / "d1_targeted_identity_ghsa.jsonl"
    if swap_path is None:
        swap_path = AUDIT / "d1_targeted_swap_ghsa.jsonl"

    if not Path(ident_path).exists():
        sys.exit(f"Identity predictions not found: {ident_path}")

    rows = S.read(f"{ROOT}/data/ghsa-eval/labels.jsonl")
    relabel = {r["id"]: r for r in json.loads(
        (AUDIT / "relabel.json").read_text(encoding="utf-8"))}
    strict = np.array([S.family(r["cwe"]) in {S.family(c) for c in r.get("finding_cwes", [])}
                       for r in rows])
    hunk = np.array([relabel[r["id"]]["hunk_tp"] for r in rows])
    stored = np.array([r["label"] == "TP" for r in rows])
    defs = {
        "L0 location proxy": stored,
        "L1 hunk only": hunk,
        "L2 stored + CWE": stored & strict,
        "L3 hunk + CWE": hunk & strict,
    }
    ent = np.array([r["vul_id"] for r in rows])
    rules = np.array([r["rule"].split(".")[-1] for r in rows])
    base = np.array([float(r["p_tp"]) for r in rows])

    ident_preds = {r["id"]: float(r["p_tp"]) for r in read(ident_path)}
    ident = np.array([ident_preds[r["id"]] for r in rows])

    has_swap = Path(swap_path).exists()
    if has_swap:
        swap_preds = {r["id"]: float(r["p_tp"]) for r in read(swap_path)}
        swap = np.array([swap_preds[r["id"]] for r in rows])
    else:
        swap = None

    print("\n=======================================================")
    print("  TARGETED SINK EVALUATION REPORT (d1-3B)")
    print("=======================================================")

    results = {}
    for dname, y in defs.items():
        y = y.astype(int)
        pos = int(y.sum())
        h_auc = S.auc(y, base)
        h_p90 = S.p_at_r(y, base)[0]

        i_auc = S.auc(y, ident)
        i_p90 = S.p_at_r(y, ident)[0]
        i_boot = S.bootstrap_delta(y, base, ident, ent)
        i_gate = bool(i_auc >= h_auc + 0.02 and i_p90 >= h_p90)

        i_within = B.weighted_within_rule(y, ident, rules)
        i_within_boot = B.bootstrap_within(y, ident, rules, ent)

        out_d = {
            "positives": pos,
            "heuristic": {"auc": round(h_auc, 4), "p_at_90r": round(h_p90, 4)},
            "targeted_identity": {
                "auc": round(i_auc, 4),
                "p_at_90r": round(i_p90, 4),
                "delta_auc": round(i_auc - h_auc, 4),
                "ci": [i_boot["low"], i_boot["high"]],
                "gate": "PASS" if i_gate else "FAIL",
                "within_rule_auc": round(float(i_within), 4),
                "within_rule_ci": [i_within_boot["low"], i_within_boot["high"]],
            }
        }

        print(f"\n{dname} ({pos} TP):")
        print(f"  Heuristic Baseline : AUC {h_auc:.4f} | P@90R {h_p90:.4f}")
        print(f"  Targeted Identity  : AUC {i_auc:.4f} | P@90R {i_p90:.4f} | dAUC {i_auc - h_auc:+.4f} [{i_boot['low']:+.3f}, {i_boot['high']:+.3f}] -> {out_d['targeted_identity']['gate']}")
        print(f"  Within-Rule AUC    : {i_within:.4f} [{i_within_boot['low']:.3f}, {i_within_boot['high']:.3f}] (share <= 0.5: {i_within_boot['share_le_0.5']:.3f})")

        if has_swap:
            s_auc = S.auc(y, swap)
            s_p90 = S.p_at_r(y, swap)[0]
            s_within = B.weighted_within_rule(y, swap, rules)
            code_diff_auc = i_auc - s_auc
            out_d["targeted_swap"] = {
                "auc": round(s_auc, 4),
                "within_rule_auc": round(float(s_within), 4),
                "code_signal_delta": round(code_diff_auc, 4),
            }
            print(f"  Targeted Swap (ctrl): AUC {s_auc:.4f} | Within-Rule {s_within:.4f} | Code Signal Delta: {code_diff_auc:+.4f}")

        results[dname] = out_d

    out_file = AUDIT / "score-d1_targeted.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nwrote {out_file}\n")


if __name__ == "__main__":
    p_id = sys.argv[1] if len(sys.argv) > 1 else None
    p_sw = sys.argv[2] if len(sys.argv) > 2 else None
    main(p_id, p_sw)
