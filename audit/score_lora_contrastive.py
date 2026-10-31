"""Score the Contrastive LoRA run across GHSA (identity + swap) and Vul4J.

Usage: python score_lora_contrastive.py
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


def main(ghsa_ident=None, ghsa_swap=None, vul4j_ident=None):
    if ghsa_ident is None:
        ghsa_ident = AUDIT / "d1_lora_identity_ghsa.jsonl"
    if ghsa_swap is None:
        ghsa_swap = AUDIT / "d1_lora_swap_ghsa.jsonl"
    if vul4j_ident is None:
        vul4j_ident = AUDIT / "d1_lora_identity_vul4j.jsonl"

    if not Path(ghsa_ident).exists():
        sys.exit(f"GHSA Identity predictions not found: {ghsa_ident}")

    # --- GHSA Evaluation ---
    ghsa_rows = S.read(f"{ROOT}/data/ghsa-eval/labels.jsonl")
    relabel = {r["id"]: r for r in json.loads(
        (AUDIT / "relabel.json").read_text(encoding="utf-8"))}
    strict = np.array([S.family(r["cwe"]) in {S.family(c) for c in r.get("finding_cwes", [])}
                       for r in ghsa_rows])
    hunk = np.array([relabel[r["id"]]["hunk_tp"] for r in ghsa_rows])
    stored = np.array([r["label"] == "TP" for r in ghsa_rows])
    defs = {
        "L0 location proxy": stored,
        "L1 hunk only": hunk,
        "L2 stored + CWE": stored & strict,
        "L3 hunk + CWE": hunk & strict,
    }
    ent = np.array([r["vul_id"] for r in ghsa_rows])
    rules = np.array([r["rule"].split(".")[-1] for r in ghsa_rows])
    base = np.array([float(r["p_tp"]) for r in ghsa_rows])

    ident_preds = {r["id"]: float(r["p_tp"]) for r in read(ghsa_ident)}
    ident = np.array([ident_preds[r["id"]] for r in ghsa_rows])

    has_swap = Path(ghsa_swap).exists()
    if has_swap:
        swap_preds = {r["id"]: float(r["p_tp"]) for r in read(ghsa_swap)}
        swap = np.array([swap_preds[r["id"]] for r in ghsa_rows])
    else:
        swap = None

    print("\n=======================================================")
    print("  CONTRASTIVE LoRA CHAMPION EVALUATION (d1-3B) - GHSA")
    print("=======================================================")

    results = {"ghsa": {}}
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
            "champion_identity": {
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
        print(f"  Champion Identity  : AUC {i_auc:.4f} | P@90R {i_p90:.4f} | dAUC {i_auc - h_auc:+.4f} [{i_boot['low']:+.3f}, {i_boot['high']:+.3f}] -> {out_d['champion_identity']['gate']}")
        print(f"  Within-Rule AUC    : {i_within:.4f} [{i_within_boot['low']:.3f}, {i_within_boot['high']:.3f}] (share <= 0.5: {i_within_boot['share_le_0.5']:.3f})")

        if has_swap:
            s_auc = S.auc(y, swap)
            s_within = B.weighted_within_rule(y, swap, rules)
            code_diff_auc = i_auc - s_auc
            out_d["champion_swap"] = {
                "auc": round(s_auc, 4),
                "within_rule_auc": round(float(s_within), 4),
                "code_signal_delta": round(code_diff_auc, 4),
            }
            print(f"  Champion Swap (ctrl): AUC {s_auc:.4f} | Within-Rule {s_within:.4f} | Code Signal Delta: {code_diff_auc:+.4f}")

        results["ghsa"][dname] = out_d

    # --- Vul4J Evaluation ---
    if Path(vul4j_ident).exists():
        print("\n=======================================================")
        print("  CONTRASTIVE LoRA CHAMPION EVALUATION (d1-3B) - Vul4J")
        print("=======================================================")
        v_rows = read(f"{ROOT}/data/vul4j-eval/scan-labeled.jsonl")
        v_y = np.array([1 if r["label"] == "TP" else 0 for r in v_rows], dtype=int)
        v_base = np.array([float(r["p_tp"]) for r in v_rows])
        v_ident_map = {r["id"]: float(r["p_tp"]) for r in read(vul4j_ident)}
        v_ident = np.array([v_ident_map[r["id"]] for r in v_rows])

        vh_auc = S.auc(v_y, v_base)
        vh_p90 = S.p_at_r(v_y, v_base)[0]
        vi_auc = S.auc(v_y, v_ident)
        vi_p90 = S.p_at_r(v_y, v_ident)[0]
        v_gate = bool(vi_auc >= vh_auc + 0.02 and vi_p90 >= vh_p90)

        results["vul4j"] = {
            "rows": len(v_rows),
            "positives": int(v_y.sum()),
            "heuristic": {"auc": round(vh_auc, 4), "p_at_90r": round(vh_p90, 4)},
            "champion_identity": {
                "auc": round(vi_auc, 4),
                "p_at_90r": round(vi_p90, 4),
                "delta_auc": round(vi_auc - vh_auc, 4),
                "gate": "PASS" if v_gate else "FAIL",
            }
        }
        print(f"Vul4J ({len(v_rows)} rows, {int(v_y.sum())} TP):")
        print(f"  Heuristic Baseline : AUC {vh_auc:.4f} | P@90R {vh_p90:.4f}")
        print(f"  Champion Identity  : AUC {vi_auc:.4f} | P@90R {vi_p90:.4f} | dAUC {vi_auc - vh_auc:+.4f} -> {results['vul4j']['champion_identity']['gate']}")

    out_file = AUDIT / "score-d1_champion.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nwrote {out_file}\n")


if __name__ == "__main__":
    main()
