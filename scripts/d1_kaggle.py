"""B6: score Vul4J alerts with LiquidAI/d1-3B as a yes/no decision.

Self-contained on purpose: the Kaggle runner gets this file as its payload,
so it must not import triage. Writes id, p_tp, confidence per row, which is
what scripts/vul4j_gate.py expects.

Usage on Kaggle: python d1_kaggle.py
Usage locally:   python scripts/d1_kaggle.py
"""
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

MODEL = "LiquidAI/d1-3B"
DATA_URL = ("https://huggingface.co/datasets/barryallen16/triagemate/"
            "resolve/main/vul4j-scan-labeled.jsonl")
OUT = Path("/kaggle/working/d1_vul4j.jsonl")
if not OUT.parent.exists():
    OUT = Path("/tmp/d1_vul4j.jsonl")
MAX_CHARS = 18000

QUESTION = ("Is this static-analysis warning a real, exploitable security bug "
            "in the code below? Answer yes only if the vulnerable pattern is "
            "present and reachable in this code.")


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
    print(f"scoring {len(rows)} rows with {MODEL}", flush=True)

    model = AutoModel.from_pretrained(MODEL, trust_remote_code=True,
                                      dtype=torch.float16).to("cuda")
    questions = {"tp": {"type": "noul", "instructions": QUESTION}}

    OUT.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    with OUT.open("w", encoding="utf-8") as fh:
        for i, row in enumerate(rows, 1):
            t0 = time.time()
            answer = model.system_one(state_of(row), questions)
            p_tp = float(answer["answers"]["tp"]["noul"])
            fh.write(json.dumps({
                "id": row["id"],
                "label": row["label"],
                "p_tp": p_tp,
                "confidence": round(max(p_tp, 1.0 - p_tp), 6),
                "seconds": round(time.time() - t0, 3),
            }) + "\n")
            if i % 10 == 0 or i == len(rows):
                print(f"  {i}/{len(rows)}  {time.time() - started:.0f}s", flush=True)
    print(f"predictions written to {OUT}", flush=True)


if __name__ == "__main__":
    main()
