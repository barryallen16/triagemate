"""Swap-window control for d1-3B with criteria.

Keeps every row's rule, CWE, severity, file, line and message, and replaces its
code window with another row's window. If d1 actually reads the code, swapping
windows should break the code-label link and move AUC toward chance. If d1 only
uses rule metadata, the score per row barely changes and AUC stays near the
unswapped 0.7028.

Two variants:
- global: window taken from any other row (derangement, no row keeps its own).
- rule: window taken from another row with the same rule; singleton rules keep
  their own window and are flagged in the plan.

Usage on Kaggle: python d1_swap_kaggle.py
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

MODEL = "LiquidAI/d1-3B"
DATA_URL = os.environ.get(
    "TRIGEMATE_DATA_URL",
    "https://huggingface.co/datasets/barryallen16/triagemate/"
    "resolve/main/ghsa-scan-labeled.jsonl")
OUT = Path(os.environ.get("TRIGEMATE_OUT", "/kaggle/working/d1_swap_ghsa.jsonl"))
PLAN = Path("/kaggle/working/swap_plan.json")
if not OUT.parent.exists():
    OUT, PLAN = Path("/tmp/d1_swap_ghsa.jsonl"), Path("/tmp/swap_plan.json")
MAX_CHARS = 18000
BATCH = 1
SEED = 3407
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

QUESTION = ("Is this static-analysis warning a real, exploitable security bug "
            "in the code below? Answer yes only if the vulnerable pattern is "
            "present and reachable in this code.")
CRITERIA = {
    "true": "The code contains the unsafe pattern named by the rule, and "
            "untrusted input can reach it without an effective guard.",
    "false": "The pattern is absent or neutralized, or the code is unreachable "
             "from untrusted input, or the alert is style-only.",
}


def state_of(row, window):
    """The alert metadata unchanged, the code window taken from the swap plan."""
    lines = [
        f"Rule: {row['rule']}",
        f"CWE: {row['cwe']}",
        f"Severity: {row.get('severity', 'WARNING')}",
        f"File: {str(row['file']).split('/')[-1]}",
        f"Line: {row.get('line', 0)}",
    ]
    if row.get("message"):
        lines.append(f"Rule message: {row['message']}")
    return "\n".join(lines) + f"\n\nJava:\n```java\n{window[:MAX_CHARS]}\n```"


def derange(indices, rng):
    """Random permutation with no fixed point."""
    idx = list(indices)
    for _ in range(100):
        perm = list(idx)
        rng.shuffle(perm)
        if len(idx) < 2 or all(a != b for a, b in zip(idx, perm)):
            return perm
    return idx[1:] + idx[:1]


def build_plan(rows):
    import random
    rng = random.Random(SEED)
    ids = [r["id"] for r in rows]
    pos = {rid: i for i, rid in enumerate(ids)}
    global_src = derange(list(range(len(rows))), rng)
    by_rule = {}
    for i, r in enumerate(rows):
        by_rule.setdefault(r["rule"], []).append(i)
    rule_src = list(range(len(rows)))
    for rule, idx in sorted(by_rule.items()):
        perm = derange(idx, rng)
        for a, b in zip(idx, perm):
            rule_src[a] = b
    plan = {
        "seed": SEED,
        "global": {ids[i]: ids[global_src[i]] for i in range(len(rows))},
        "rule": {ids[i]: ids[rule_src[i]] for i in range(len(rows))},
        "rule_singletons": sorted(rule for rule, idx in by_rule.items() if len(idx) < 2),
    }
    return plan, pos


def main():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "transformers>=5.14", "accelerate"])
    import torch
    from transformers import AutoModel

    rows = [json.loads(line) for line in
            urllib.request.urlopen(DATA_URL, timeout=120).read().decode().splitlines()
            if line.strip()]
    plan, pos = build_plan(rows)
    by_id = {r["id"]: r for r in rows}
    jobs = []
    for variant in ("global", "rule"):
        for r in rows:
            src = by_id[plan[variant][r["id"]]]
            jobs.append((variant, r, src["code_window"]))
    print(f"scoring {len(jobs)} rows ({len(rows)} x 2 variants) with {MODEL}",
          flush=True)
    print(f"rule singletons keep own window: {plan['rule_singletons']}", flush=True)

    model = AutoModel.from_pretrained(MODEL, trust_remote_code=True,
                                      dtype=torch.float16).to("cuda")
    questions = {"tp": {"type": "noul", "instructions": QUESTION,
                        "criteria": CRITERIA}}

    OUT.parent.mkdir(parents=True, exist_ok=True)
    PLAN.write_text(json.dumps(plan), encoding="utf-8")
    started = time.time()
    with OUT.open("w", encoding="utf-8") as fh:
        for start in range(0, len(jobs), BATCH):
            chunk = jobs[start:start + BATCH]
            t0 = time.time()
            answers = model.system_one_batch(
                [(state_of(r, window), questions) for _, r, window in chunk])
            elapsed = time.time() - t0
            for (variant, row, _), answer in zip(chunk, answers):
                fh.write(json.dumps({
                    "id": row["id"],
                    "variant": variant,
                    "label": row["label"],
                    "p_tp": float(answer["answers"]["tp"]["noul"]),
                    "seconds": round(elapsed / len(chunk), 3),
                }) + "\n")
            fh.flush()
            done = min(start + BATCH, len(jobs))
            if done % 20 == 0 or done == len(jobs):
                print(f"  {done}/{len(jobs)}  {time.time() - started:.0f}s",
                      flush=True)
    print(f"predictions written to {OUT}", flush=True)


if __name__ == "__main__":
    main()
