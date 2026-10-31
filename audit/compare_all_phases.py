import json
from pathlib import Path
import numpy as np

import baselines as B
import sensitivity as S

AUDIT = Path(__file__).resolve().parent
REPO = AUDIT.parent.parent if AUDIT.parent.name == "work" else AUDIT.parent
DATA = REPO / "data" if (REPO / "data").exists() else REPO / "work" / "data"

ghsa_rows = S.read(str(DATA / "ghsa-eval" / "labels.jsonl"))
relabel = {r["id"]: r for r in json.loads((AUDIT / "relabel.json").read_text(encoding="utf-8"))}
strict = np.array([S.family(r["cwe"]) in {S.family(c) for c in r.get("finding_cwes", [])} for r in ghsa_rows])
hunk = np.array([relabel[r["id"]]["hunk_tp"] for r in ghsa_rows])
stored = np.array([r["label"] == "TP" for r in ghsa_rows])
defs = {
    "L0": stored,
    "L1": hunk,
    "L2": stored & strict,
    "L3": hunk & strict,
}
ent = np.array([r["vul_id"] for r in ghsa_rows])
rules = np.array([r["rule"].split(".")[-1] for r in ghsa_rows])
base = np.array([float(r["p_tp"]) for r in ghsa_rows])

v_rows = [json.loads(l) for l in open(DATA / "vul4j-eval" / "scan-labeled.jsonl", encoding="utf-8") if l.strip()]
v_y = np.array([1 if r["label"] == "TP" else 0 for r in v_rows], dtype=int)
v_base = np.array([float(r["p_tp"]) for r in v_rows])


def read_preds(path):
    p = Path(path)
    if not p.exists():
        return None
    return {r["id"]: float(r["p_tp"]) for r in [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]}


runs = {
    "Heuristic Baseline": (None, None, None),
    "1. Baseline D1 (Audit)": (DATA / "ghsa-eval" / "d1_predictions.jsonl", AUDIT / "d1_swap_predictions.jsonl", DATA / "vul4j-eval" / "d1_predictions.jsonl"),
    "2. Phase 2 (Targeted Sink)": (AUDIT / "d1_targeted_identity_ghsa.jsonl", AUDIT / "d1_targeted_swap_ghsa.jsonl", None),
    "3. Phase 2b (Sink + Hybrid Criteria)": (AUDIT / "d1_targeted_criteria_identity_ghsa.jsonl", AUDIT / "d1_targeted_criteria_swap_ghsa.jsonl", AUDIT / "d1_targeted_criteria_identity_vul4j.jsonl"),
    "4. Phase 3 (Contrastive LoRA)": (AUDIT / "d1_lora_identity_ghsa.jsonl", AUDIT / "d1_lora_swap_ghsa.jsonl", AUDIT / "d1_lora_identity_vul4j.jsonl"),
}

print(f"{'Variant':<35} | {'L0 AUC':<7} | {'L0 W-AUC':<8} | {'L0 Code-D':<9} | {'L2 AUC':<7} | {'L2 W-AUC':<8} | {'L2 Code-D':<9} | {'L3 W-AUC':<8} | {'Vul4J AUC'}")
print("-" * 125)

for name, (i_path, s_path, v_path) in runs.items():
    if name == "Heuristic Baseline":
        l0_auc = S.auc(defs["L0"].astype(int), base)
        l0_w = B.weighted_within_rule(defs["L0"].astype(int), base, rules)
        l2_auc = S.auc(defs["L2"].astype(int), base)
        l2_w = B.weighted_within_rule(defs["L2"].astype(int), base, rules)
        l3_w = B.weighted_within_rule(defs["L3"].astype(int), base, rules)
        v_auc = S.auc(v_y, v_base)
        print(f"{name:<35} | {l0_auc:.4f}  | {l0_w:.4f}   | {'N/A':<9} | {l2_auc:.4f}  | {l2_w:.4f}   | {'N/A':<9} | {l3_w:.4f}   | {v_auc:.4f}")
        continue

    i_map = read_preds(i_path)
    s_map = read_preds(s_path)
    if not i_map:
        continue
    i_arr = np.array([i_map[r["id"]] for r in ghsa_rows])
    s_arr = np.array([s_map[r["id"]] for r in ghsa_rows]) if s_map else None

    l0_auc = S.auc(defs["L0"].astype(int), i_arr)
    l0_w = B.weighted_within_rule(defs["L0"].astype(int), i_arr, rules)
    l0_cd = (l0_auc - S.auc(defs["L0"].astype(int), s_arr)) if s_arr is not None else 0.0

    l2_auc = S.auc(defs["L2"].astype(int), i_arr)
    l2_w = B.weighted_within_rule(defs["L2"].astype(int), i_arr, rules)
    l2_cd = (l2_auc - S.auc(defs["L2"].astype(int), s_arr)) if s_arr is not None else 0.0

    l3_w = B.weighted_within_rule(defs["L3"].astype(int), i_arr, rules)

    v_auc_str = "N/A"
    if v_path and Path(v_path).exists():
        v_map = read_preds(v_path)
        v_arr = np.array([v_map[r["id"]] for r in v_rows])
        v_auc_str = f"{S.auc(v_y, v_arr):.4f}"

    print(f"{name:<35} | {l0_auc:.4f}  | {l0_w:.4f}   | {l0_cd:+.4f}   | {l2_auc:.4f}  | {l2_w:.4f}   | {l2_cd:+.4f}   | {l3_w:.4f}   | {v_auc_str}")
