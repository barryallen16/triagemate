"""Within-rule AUC and entry bootstrap for the d1 LoRA under L0 to L3."""
import json
import numpy as np
import baselines as B
import sensitivity as S

from pathlib import Path

AUDIT = str(Path(__file__).resolve().parent)
rows = S.read(f"{S.ROOT}/data/ghsa-eval/labels.jsonl")
relabel = {r["id"]: r for r in json.loads(open(f"{AUDIT}/relabel.json").read())}
by = {r["id"]: float(r["p_tp"]) for r in S.read(f"{AUDIT}/d1_lora_predictions.jsonl")}
pred = np.array([by[r["id"]] for r in rows])
base = np.array([float(r["p_tp"]) for r in rows])
ent = np.array([r["vul_id"] for r in rows])
rules = np.array([r["rule"].split(".")[-1] for r in rows])
strict = np.array([S.family(r["cwe"]) in {S.family(c) for c in r.get("finding_cwes", [])} for r in rows])
hunk = np.array([relabel[r["id"]]["hunk_tp"] for r in rows])
stored = np.array([r["label"] == "TP" for r in rows])
defs = {"L0": stored, "L1": hunk, "L2": stored & strict, "L3": hunk & strict}
out = {}
for name, y in defs.items():
    y = y.astype(int)
    w = float(B.weighted_within_rule(y, pred, rules))
    wb = float(B.weighted_within_rule(y, base, rules))
    b = B.bootstrap_within(y, pred, rules, ent)
    out[name] = {"within_rule_lora": round(w, 4), "within_rule_heuristic": round(wb, 4), "entry_bootstrap": b}
    lo, hi, sh = b["low"], b["high"], b["share_le_0.5"]
    print("%s: lora within %.4f heuristic within %.4f CI [%+.3f,%+.3f] share<=0.5 %.3f" % (name, w, wb, lo, hi, sh))
prev = json.load(open(f"{AUDIT}/score-d1_lora.json"))
prev["within_rule"] = out
open(f"{AUDIT}/score-d1_lora.json", "w").write(json.dumps(prev, indent=2))
print("wrote score-d1_lora.json")
