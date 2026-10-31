import json
from pathlib import Path

AUDIT = Path(__file__).resolve().parent

sens = json.loads((AUDIT / "sensitivity.json").read_text(encoding="utf-8"))
base = json.loads((AUDIT / "baselines.json").read_text(encoding="utf-8"))
tgt = json.loads((AUDIT / "score-d1_targeted.json").read_text(encoding="utf-8"))

print("\n### Complete Model Evaluation & Gating Comparison")
print("| Def | Pos | Metric | Heuristic | d1 Zero-shot (3B) | Kev-4B (4B) | d1 Targeted Sink (3B) | Code Delta vs Swap |")
print("|---|---|---|---|---|---|---|---|")

defs = ["L0 location proxy", "L1 hunk only", "L2 stored + CWE", "L3 hunk + CWE"]
for d in defs:
    short = d[:2]
    pos = sens[d]["positives"]
    
    h_auc = sens[d]["scores"]["heuristic"]["auc"]
    h_p90 = sens[d]["scores"]["heuristic"]["p_at_90r"]
    
    d1_auc = sens[d]["scores"]["d1"]["auc"]
    d1_p90 = sens[d]["scores"]["d1"]["p_at_90r"]
    d1_gate = "PASS" if sens[d]["scores"]["d1"]["gate_pass"] else "FAIL"
    
    kev_auc = sens[d]["scores"]["kev"]["auc"]
    kev_p90 = sens[d]["scores"]["kev"]["p_at_90r"]
    kev_gate = "PASS" if sens[d]["scores"]["kev"]["gate_pass"] else "FAIL"
    
    t_auc = tgt[d]["targeted_identity"]["auc"]
    t_p90 = tgt[d]["targeted_identity"]["p_at_90r"]
    t_gate = tgt[d]["targeted_identity"]["gate"]
    t_delta_swap = tgt[d]["targeted_swap"]["code_signal_delta"]
    
    d1_within = base["within_rule"][d]["d1"]["auc"]
    kev_within = base["within_rule"][d]["kev"]["auc"]
    t_within = tgt[d]["targeted_identity"]["within_rule_auc"]
    
    print(f"| {short} | {pos} | AUC | {h_auc:.4f} | {d1_auc:.4f} ({d1_gate}) | {kev_auc:.4f} ({kev_gate}) | **{t_auc:.4f}** ({t_gate}) | **{t_delta_swap:+.4f}** |")
    print(f"| {short} | {pos} | P@90R | {h_p90:.4f} | {d1_p90:.4f} | {kev_p90:.4f} | **{t_p90:.4f}** | - |")
    print(f"| {short} | {pos} | Within-Rule AUC | 0.5000 | {d1_within:.4f} | {kev_within:.4f} | **{t_within:.4f}** | - |")
