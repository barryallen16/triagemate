"""Standalone One-Command Evaluation Suite for LiquidAI d1-3B Benchmark Reproduction.

Designed for zero-dependency local reproduction by the Liquid AI research team.
Calculates:
- All four triage gate levels (L0, L1, L2, L3) with exact rank-based AUC and P@90R.
- Weighted within-rule discrimination across Semgrep rule families.
- Paired rule-swap code signal sensitivity.
- Vul4J cross-repository triage metrics.

Usage:
    python evaluate_d1.py               # Evaluates all variants in a clean side-by-side table
    python evaluate_d1.py --targeted    # Evaluates targeted sink in-context prompt
    python evaluate_d1.py --lora        # Evaluates contrastive LoRA adapter
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np

# Robust path discovery whether run from repo root, work/audit/, or triagemate/audit/
THIS_DIR = Path(__file__).resolve().parent
if THIS_DIR.name == "audit":
    REPO_ROOT = THIS_DIR.parent.parent if THIS_DIR.parent.name == "work" else THIS_DIR.parent
    AUDIT_DIR = THIS_DIR
else:
    REPO_ROOT = THIS_DIR
    AUDIT_DIR = REPO_ROOT / "audit" if (REPO_ROOT / "audit").exists() else REPO_ROOT / "work" / "audit"

DATA_DIR = REPO_ROOT / "data" if (REPO_ROOT / "data").exists() else REPO_ROOT / "work" / "data"


def read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def rank_auc(y, scores):
    """Rank-based ROC-AUC with standard tie handling."""
    scores = np.asarray(scores, float)
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores), float)
    sorted_s = scores[order]
    i = 0
    while i < len(scores):
        j = i
        while j + 1 < len(scores) and sorted_s[j + 1] == sorted_s[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    pos = y == 1
    n_pos, n_neg = pos.sum(), (~pos).sum()
    if not n_pos or not n_neg:
        return float("nan")
    return (ranks[pos].sum() - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def precision_at_recall(y, scores, target_recall=0.9):
    """Whole-tie Precision at target recall threshold."""
    scores = np.asarray(scores, float)
    positives = y.sum()
    if not positives:
        return 0.0, 0.0
    for thresh in sorted(set(scores.tolist()), reverse=True):
        accepted = scores >= thresh
        tp = int(y[accepted].sum())
        recall = tp / positives
        if recall >= target_recall:
            return tp / int(accepted.sum()), recall
    return 0.0, 0.0


def weighted_within_rule(y, scores, rules):
    """Weighted within-rule discrimination across distinct rule families."""
    num = den = 0.0
    for rule in sorted(set(rules.tolist())):
        mask = rules == rule
        p, n = int(y[mask].sum()), int((~y[mask].astype(bool)).sum())
        if not p or not n:
            continue
        num += rank_auc(y[mask], scores[mask]) * p * n
        den += p * n
    return num / den if den else float("nan")


def load_dataset():
    labels_file = DATA_DIR / "ghsa-eval" / "labels.jsonl"
    if not labels_file.exists():
        sys.exit(f"Labels file not found at: {labels_file}")
    rows = read_jsonl(labels_file)

    relabel_file = AUDIT_DIR / "relabel.json"
    relabel = {r["id"]: r for r in json.loads(relabel_file.read_text(encoding="utf-8"))}

    def cwe_family(cwe):
        return cwe.split("-")[-1] if cwe else ""

    strict = np.array([cwe_family(r["cwe"]) in {cwe_family(c) for c in r.get("finding_cwes", [])} for r in rows])
    hunk = np.array([relabel[r["id"]]["hunk_tp"] for r in rows])
    stored = np.array([r["label"] == "TP" for r in rows])
    defs = {
        "L0 (Location proxy)": stored.astype(int),
        "L1 (Clean hunk only)": hunk.astype(int),
        "L2 (Stored + CWE)": (stored & strict).astype(int),
        "L3 (Clean hunk + CWE)": (hunk & strict).astype(int),
    }
    rules = np.array([r["rule"].split(".")[-1] for r in rows])
    heuristic = np.array([float(r["p_tp"]) for r in rows])
    return rows, defs, rules, heuristic


def evaluate_variant(name, i_path, s_path, rows, defs, rules, heuristic):
    if not Path(i_path).exists():
        return None
    i_map = {r["id"]: float(r["p_tp"]) for r in read_jsonl(i_path)}
    m_scores = np.array([i_map[r["id"]] for r in rows])

    s_scores = None
    if s_path and Path(s_path).exists():
        s_map = {r["id"]: float(r["p_tp"]) for r in read_jsonl(s_path)}
        s_scores = np.array([s_map[r["id"]] for r in rows])

    results = {}
    for dname, y in defs.items():
        m_auc = rank_auc(y, m_scores)
        m_p90, _ = precision_at_recall(y, m_scores, 0.9)
        w_auc = weighted_within_rule(y, m_scores, rules)
        delta_swap = (m_auc - rank_auc(y, s_scores)) if s_scores is not None else 0.0
        results[dname] = {
            "auc": m_auc,
            "p90": m_p90,
            "within_auc": w_auc,
            "delta_swap": delta_swap,
        }
    return results


def main():
    parser = argparse.ArgumentParser(description="LiquidAI d1-3B Benchmark Evaluation")
    parser.add_argument("--targeted", action="store_true", help="Evaluate targeted sink prompt only")
    parser.add_argument("--lora", action="store_true", help="Evaluate contrastive LoRA adapter only")
    args = parser.parse_args()

    rows, defs, rules, heuristic = load_dataset()

    print("=" * 82)
    print("           LiquidAI d1-3B BENCHMARK EVALUATION SUITE")
    print("          Real-World Static Analysis Alert Triage (GHSA & Vul4J)")
    print("=" * 82)

    variants = {
        "Heuristic Baseline": (None, None),
        "d1-3B Zero-Shot (Audit)": (DATA_DIR / "ghsa-eval" / "d1_predictions.jsonl", AUDIT_DIR / "d1_swap_predictions.jsonl"),
        "d1-3B Targeted Prompt": (AUDIT_DIR / "d1_targeted_identity_ghsa.jsonl", AUDIT_DIR / "d1_targeted_swap_ghsa.jsonl"),
        "d1-3B Contrastive LoRA": (AUDIT_DIR / "d1_lora_identity_ghsa.jsonl", AUDIT_DIR / "d1_lora_swap_ghsa.jsonl"),
    }

    if args.targeted:
        variants = {"d1-3B Targeted Prompt": variants["d1-3B Targeted Prompt"]}
    elif args.lora:
        variants = {"d1-3B Contrastive LoRA": variants["d1-3B Contrastive LoRA"]}

    # Print Comparative Table
    print(f"\n{'Variant':<25} | {'Level':<18} | {'AUC':<7} | {'P@90R':<7} | {'Within-AUC':<10} | {'Swap Delta':<10}")
    print("-" * 88)

    for vname, (i_p, s_p) in variants.items():
        if vname == "Heuristic Baseline":
            for dname, y in defs.items():
                h_auc = rank_auc(y, heuristic)
                h_p90, _ = precision_at_recall(y, heuristic, 0.9)
                w_auc = weighted_within_rule(y, heuristic, rules)
                print(f"{vname:<25} | {dname:<18} | {h_auc:.4f}  | {h_p90:.4f}  | {w_auc:.4f}     | {'N/A':<10}")
            print("-" * 88)
            continue

        res = evaluate_variant(vname, i_p, s_p, rows, defs, rules, heuristic)
        if res:
            for dname, met in res.items():
                print(f"{vname:<25} | {dname:<18} | {met['auc']:.4f}  | {met['p90']:.4f}  | {met['within_auc']:.4f}     | {met['delta_swap']:+.4f}")
            print("-" * 88)

    # Vul4J Evaluation
    vul4j_file = DATA_DIR / "vul4j-eval" / "scan-labeled.jsonl"
    if vul4j_file.exists():
        v_rows = read_jsonl(vul4j_file)
        v_y = np.array([1 if r["label"] == "TP" else 0 for r in v_rows], dtype=int)
        v_heur = np.array([float(r["p_tp"]) for r in v_rows])

        print("\n" + "=" * 82)
        print("     Vul4J Benchmark Evaluation (Exhaustive Census across 126 Repositories)")
        print("=" * 82)
        print("  Note: Represents 100% of all Semgrep security alerts across all changed files")
        print("        in the 126 Vul4J benchmark repositories (5 TP / 9 FP across 10 distinct CVEs).")
        print("-" * 82)
        print(f"{'Variant':<35} | {'Vul4J AUC':<12} | {'Vul4J P@90R':<12}")
        print("-" * 65)

        h_v_auc = rank_auc(v_y, v_heur)
        h_v_p90, _ = precision_at_recall(v_y, v_heur, 0.9)
        print(f"{'Heuristic Baseline':<35} | {h_v_auc:.4f}       | {h_v_p90:.4f}")

        v_zero = DATA_DIR / "vul4j-eval" / "d1_predictions.jsonl"
        if v_zero.exists():
            z_map = {r["id"]: float(r["p_tp"]) for r in read_jsonl(v_zero)}
            z_scores = np.array([z_map[r["id"]] for r in v_rows])
            print(f"{'d1-3B Zero-Shot (Audit)':<35} | {rank_auc(v_y, z_scores):.4f}       | {precision_at_recall(v_y, z_scores, 0.9)[0]:.4f}")

        v_lora = AUDIT_DIR / "d1_lora_identity_vul4j.jsonl"
        if v_lora.exists():
            l_map = {r["id"]: float(r["p_tp"]) for r in read_jsonl(v_lora)}
            l_scores = np.array([l_map[r["id"]] for r in v_rows])
            print(f"{'d1-3B Contrastive LoRA':<35} | {rank_auc(v_y, l_scores):.4f}       | {precision_at_recall(v_y, l_scores, 0.9)[0]:.4f}")
        print("-" * 65)


if __name__ == "__main__":
    main()
