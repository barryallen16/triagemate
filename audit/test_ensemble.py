import json
from pathlib import Path
import numpy as np
import baselines as B
import sensitivity as S

ghsa_rows = S.read("work/data/ghsa-eval/labels.jsonl")
relabel = {r["id"]: r for r in json.loads(Path("work/audit/relabel.json").read_text(encoding="utf-8"))}
strict = np.array([S.family(r["cwe"]) in {S.family(c) for c in r.get("finding_cwes", [])} for r in ghsa_rows])
hunk = np.array([relabel[r["id"]]["hunk_tp"] for r in ghsa_rows])
stored = np.array([r["label"] == "TP" for r in ghsa_rows])
defs = {
    "L0": stored.astype(int),
    "L1": hunk.astype(int),
    "L2": (stored & strict).astype(int),
    "L3": (hunk & strict).astype(int),
}
ent = np.array([r["vul_id"] for r in ghsa_rows])
rules = np.array([r["rule"].split(".")[-1] for r in ghsa_rows])
base = np.array([float(r["p_tp"]) for r in ghsa_rows])

def load_p(path):
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    m = {r["id"]: float(r["p_tp"]) for r in rows}
    return np.array([m[r["id"]] for r in ghsa_rows])

p_base = load_p("work/data/ghsa-eval/d1_predictions.jsonl")
p_targeted = load_p("work/audit/d1_targeted_identity_ghsa.jsonl")
p_lora = load_p("work/audit/d1_lora_identity_ghsa.jsonl")

# Let's test combinations of p_base (rule prior) and p_targeted / p_lora (code discrimination)
print("=== Testing Ensemble Combinations ===")
for alpha in [0.0, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 1.0]:
    # Blend: alpha * p_targeted + (1 - alpha) * p_base
    blend = alpha * p_targeted + (1 - alpha) * p_base
    l0_auc = S.auc(defs["L0"], blend)
    l0_w = B.weighted_within_rule(defs["L0"], blend, rules)
    l2_auc = S.auc(defs["L2"], blend)
    l2_w = B.weighted_within_rule(defs["L2"], blend, rules)
    print(f"Alpha {alpha:.1f} (Targeted + Base) | L0 AUC: {l0_auc:.4f} | L0 W-AUC: {l0_w:.4f} | L2 AUC: {l2_auc:.4f} | L2 W-AUC: {l2_w:.4f}")

print("\n=== Testing LoRA + Targeted Blend ===")
for beta in [0.0, 0.3, 0.5, 0.7, 1.0]:
    blend = beta * p_lora + (1 - beta) * p_targeted
    l0_auc = S.auc(defs["L0"], blend)
    l0_w = B.weighted_within_rule(defs["L0"], blend, rules)
    l2_auc = S.auc(defs["L2"], blend)
    l2_w = B.weighted_within_rule(defs["L2"], blend, rules)
    l3_w = B.weighted_within_rule(defs["L3"], blend, rules)
    print(f"Beta {beta:.1f} (LoRA + Targeted) | L0 AUC: {l0_auc:.4f} | L0 W-AUC: {l0_w:.4f} | L2 AUC: {l2_auc:.4f} | L2 W-AUC: {l2_w:.4f} | L3 W-AUC: {l3_w:.4f}")
