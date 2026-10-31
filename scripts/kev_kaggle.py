"""B6: score Vul4J alerts with Kev-4B as a yes/no decision.

Self-contained on purpose: the Kaggle runner gets this file as its payload,
so it must not import triage. Writes id, p_tp, confidence per row, which is
what scripts/vul4j_gate.py expects.

Kev ships as a git repo, not a PyPI package, so the payload clones it and
loads the published checkpoint with the repo's own loader.

Usage on Kaggle: python kev_kaggle.py
Usage locally:   python scripts/kev_kaggle.py  (needs a GPU)
"""
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

MODEL = "jaredpalmer/kev-4b"
REPO = "https://github.com/jaredpalmer/kev.git"
DATA_URL = ("https://huggingface.co/datasets/barryallen16/triagemate/"
            "resolve/main/vul4j-scan-labeled.jsonl")
OUT = Path("/kaggle/working/kev_vul4j.jsonl")
if not OUT.parent.exists():
    OUT = Path("/tmp/kev_vul4j.jsonl")
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
                           "transformers>=5.17,<6", "accelerate", "peft"])
    # Kaggle ships torchao 0.10, which peft refuses at import time on the
    # versions this model needs. Nothing here uses torchao, so drop it.
    subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", "torchao"],
                          stdout=subprocess.DEVNULL)
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "--no-deps", f"git+{REPO}"])
    import torch
    from kev.api import Noul, SystemOneRequest
    from kev.checkpoint import Checkpoint, LoadOptions
    from kev.serve import Server

    rows = [json.loads(line) for line in
            urllib.request.urlopen(DATA_URL, timeout=120).read().decode().splitlines()
            if line.strip()]
    print(f"scoring {len(rows)} rows with {MODEL}", flush=True)

    ck = Checkpoint(MODEL)
    tok, model = ck.load("cuda", LoadOptions(dtype=torch.bfloat16))
    server = Server(ck, tok, model, "cuda")
    question = Noul(type="noul", instructions=QUESTION)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    with OUT.open("w", encoding="utf-8") as fh:
        for i, row in enumerate(rows, 1):
            t0 = time.time()
            body = server.answer(SystemOneRequest(
                state=state_of(row), questions={"tp": question}))
            p_tp = float(body["answers"]["tp"]["noul"])
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
