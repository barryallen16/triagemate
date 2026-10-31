"""d1-3B with explicit true/false criteria on the 174-row second set.

Same model, same state text, same readout as scripts/d1_kaggle.py; the only
change is the optional `criteria` field the d1 prompt supports. This tests the
cookbook's recommendation without changing anything else.

Usage on Kaggle: python d1_criteria_kaggle.py
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
OUT = Path(os.environ.get("TRIGEMATE_OUT", "/kaggle/working/d1_criteria_ghsa.jsonl"))
if not OUT.parent.exists():
    OUT = Path("/tmp/d1_criteria_ghsa.jsonl")
MAX_CHARS = 18000
BATCH = 1
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


def state_of(row):
    """The alert plus the code it points at, in plain text."""
    window = row.get("code_window", "")[:MAX_CHARS]
    lines = [
        f"Rule: {row['rule']}",
        f"CWE: {row['cwe']}",
        f"Severity: {row.get('severity', 'WARNING')}",
        f"File: {str(row['file']).split('/')[-1]}",
        f"Line: {row.get('line', 0)}",
    ]
    if row.get("message"):
        lines.append(f"Rule message: {row['message']}")
    return "\n".join(lines) + f"\n\nJava:\n```java\n{window}\n```"


def main():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "transformers>=5.14", "accelerate"])
    import torch
    from transformers import AutoModel

    rows = [json.loads(line) for line in
            urllib.request.urlopen(DATA_URL, timeout=120).read().decode().splitlines()
            if line.strip()]
    print(f"scoring {len(rows)} rows with {MODEL} and criteria", flush=True)

    model = AutoModel.from_pretrained(MODEL, trust_remote_code=True,
                                      dtype=torch.float16).to("cuda")
    questions = {"tp": {"type": "noul", "instructions": QUESTION,
                        "criteria": CRITERIA}}

    OUT.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    with OUT.open("w", encoding="utf-8") as fh:
        for start in range(0, len(rows), BATCH):
            chunk = rows[start:start + BATCH]
            t0 = time.time()
            answers = model.system_one_batch(
                [(state_of(row), questions) for row in chunk])
            elapsed = time.time() - t0
            for row, answer in zip(chunk, answers):
                p_tp = float(answer["answers"]["tp"]["noul"])
                fh.write(json.dumps({
                    "id": row["id"],
                    "label": row["label"],
                    "p_tp": p_tp,
                    "confidence": round(max(p_tp, 1.0 - p_tp), 6),
                    "seconds": round(elapsed / len(chunk), 3),
                }) + "\n")
            fh.flush()
            done = min(start + BATCH, len(rows))
            print(f"  {done}/{len(rows)}  {time.time() - started:.0f}s", flush=True)
    print(f"predictions written to {OUT}", flush=True)


if __name__ == "__main__":
    main()
