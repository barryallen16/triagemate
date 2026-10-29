"""Score A3 Vul4J findings with the existing QLoRA adapter on Kaggle.

Input rows and output predictions are JSONL. Prediction rows retain each input
ID and label so `scripts/vul4j_gate.py --pred qlora=...` can compare them.
"""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

SYSTEM = ("You are a Java security reviewer. You triage static analysis "
          "warnings. Answer in exactly three lines and nothing else.")
INSTRUCTIONS = ("Decide whether this warning is a true positive (a real "
                "exploitable bug) or a false positive (noise).\n\n"
                "VERDICT: TP or FP")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="/kaggle/input/vul4j-scan-labeled.jsonl")
    ap.add_argument("--out", default="/kaggle/working/vul4j_predictions.jsonl")
    ap.add_argument("--model", default="unsloth/Qwen2.5-Coder-7B-Instruct-bnb-4bit")
    ap.add_argument("--adapter-url", default="https://huggingface.co/datasets/barryallen16/triagemate/resolve/main/qlora-adapter.zip")
    args = ap.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        sys.exit(f"missing input JSONL: {input_path}")
    rows = [json.loads(line) for line in input_path.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    if not rows:
        sys.exit("input JSONL has no rows")
    if len({row["id"] for row in rows}) != len(rows):
        sys.exit("input JSONL contains duplicate IDs")

    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "unsloth", "peft", "accelerate", "bitsandbytes"])
    import torch
    if not torch.cuda.is_available():
        sys.exit("no GPU")
    import io
    import urllib.request
    import zipfile
    from unsloth import FastLanguageModel

    adapter_dir = Path("/kaggle/tmp/triagemate-adapter")
    adapter_dir.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(args.adapter_url, timeout=600) as response:
        with zipfile.ZipFile(io.BytesIO(response.read())) as archive:
            archive.extractall(adapter_dir)
    configs = list(adapter_dir.rglob("adapter_config.json"))
    if not configs:
        sys.exit("adapter archive has no adapter_config.json")

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model, max_seq_length=8192, dtype=None, load_in_4bit=True)
    from peft import PeftModel
    model = PeftModel.from_pretrained(model, str(configs[0].parent))
    FastLanguageModel.for_inference(model)
    tok_tp = tokenizer(" TP", add_special_tokens=False).input_ids[0]
    tok_fp = tokenizer(" FP", add_special_tokens=False).input_ids[0]

    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for index, row in enumerate(rows, 1):
            prompt = (f"RULE: {row['rule']}\nCWE: {row['cwe']}\n"
                      f"FILE: {Path(row['file']).name}\n"
                      f"CODE:\n```java\n{row['code_window'][:18000]}\n```\n\n"
                      f"{INSTRUCTIONS}")
            prefix = tokenizer.apply_chat_template(
                [{"role": "system", "content": SYSTEM},
                 {"role": "user", "content": prompt}],
                tokenize=False, add_generation_prompt=True) + "VERDICT:"
            encoded = tokenizer(prefix, return_tensors="pt").to(model.device)
            started = time.time()
            with torch.no_grad():
                logits = model(**encoded).logits[0, -1]
                probability = torch.softmax(
                    torch.stack([logits[tok_tp], logits[tok_fp]]), dim=0)[0].item()
            fh.write(json.dumps({"id": row["id"], "vul_id": row["vul_id"],
                                 "label": row["label"], "p_tp": probability,
                                 "rule": row["rule"], "cwe": row["cwe"],
                                 "seconds": round(time.time() - started, 2)}) + "\n")
            if index % 10 == 0 or index == len(rows):
                print(f"scored {index}/{len(rows)}", flush=True)
    print(f"predictions written to {output}", flush=True)


if __name__ == "__main__":
    main()
