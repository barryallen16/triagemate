"""Score rows with the decision model (B1 synthetic test, B4 Vul4J).

Reads JSONL rows with id, rule, cwe, file, code_window and label. Writes
id, p_tp, confidence per row, which is what scripts/vul4j_gate.py expects.

Usage:
  python scripts/decision_score.py --fetch-test --out /tmp/decision_test.jsonl
  python scripts/decision_score.py --input data/vul4j-eval/scan-labeled.jsonl \
      --out /tmp/decision_vul4j.jsonl
"""
import argparse
import json
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from triage.decision import (
    MODEL, REVISION, decision_input, option_token_ids, prompt_of,
)

TEST_URL = ("https://huggingface.co/datasets/barryallen16/triagemate/"
            "resolve/main/triage-v1.tar.gz")


def load_rows(args):
    if args.fetch_test:
        path = Path("/tmp/triage-data/triage_test.jsonl")
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tgz = path.parent / "triage-v1.tar.gz"
            if not tgz.exists():
                print("downloading triage-v1.tar.gz", flush=True)
                urllib.request.urlretrieve(TEST_URL, tgz)
            with tarfile.open(tgz) as archive:
                member = next(m for m in archive.getmembers()
                              if Path(m.name).name == "triage_test.jsonl")
                archive.extract(member, path.parent)
                path.parent.joinpath(member.name).rename(path)
        rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
                if l.strip()]
    else:
        rows = [json.loads(l) for l in Path(args.input).read_text(encoding="utf-8").splitlines()
                if l.strip()]
    ids = [r.get("id") for r in rows]
    missing = [i for i in ids if not i]
    if missing:
        sys.exit(f"{len(missing)} rows have no id")
    if len(set(ids)) != len(ids):
        sys.exit(f"input has duplicate ids: {len(ids) - len(set(ids))} extra")
    return rows[:args.limit] if args.limit else rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(ROOT / "data/vul4j-eval" / "scan-labeled.jsonl"))
    ap.add_argument("--fetch-test", action="store_true",
                    help="score the held-out synthetic test split instead of --input")
    ap.add_argument("--out", default="/tmp/decision_predictions.jsonl")
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--revision", default=REVISION)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-chars", type=int, default=18000,
                    help="clip the code window so long rows fit the sequence")
    args = ap.parse_args()

    rows = load_rows(args)
    print(f"scoring {len(rows)} rows with {args.model}@{args.revision[:12]}", flush=True)

    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "unsloth", "peft", "accelerate", "bitsandbytes"])
    import torch
    if not torch.cuda.is_available():
        sys.exit("no GPU")
    from unsloth import FastLanguageModel

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model, revision=args.revision or None,
        max_seq_length=8192, dtype=None, load_in_4bit=True)
    FastLanguageModel.for_inference(model)
    tok_tp, tok_fp = option_token_ids(tokenizer)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    started_all = time.time()
    with out.open("w", encoding="utf-8") as fh:
        for i, row in enumerate(rows, 1):
            # Clip before rendering so the whole prompt fits the sequence.
            clipped = dict(row)
            if len(clipped.get("code_window", "")) > args.max_chars:
                clipped["code_window"] = clipped["code_window"][:args.max_chars]
            decision = decision_input(clipped)
            prompt = prompt_of(clipped)
            prefix = tokenizer.apply_chat_template(
                [{"role": "system",
                  "content": "You decide one bounded question from declared options."},
                 {"role": "user", "content": prompt}],
                tokenize=False, add_generation_prompt=True) + "VERDICT:"
            ids = tokenizer(text=prefix, return_tensors="pt").to(model.device)
            t0 = time.time()
            with torch.no_grad():
                logits = model(**ids).logits[0, -1]
                p_tp = torch.softmax(
                    torch.stack([logits[tok_tp], logits[tok_fp]]), 0)[0].item()
            fh.write(json.dumps({
                "id": row["id"],
                "label": row["label"],
                "p_tp": p_tp,
                "confidence": round(max(p_tp, 1.0 - p_tp), 6),
                "seconds": round(time.time() - t0, 3),
                "question": decision["question"],
            }) + "\n")
            if i % 25 == 0 or i == len(rows):
                elapsed = time.time() - started_all
                print(f"  {i}/{len(rows)}  {elapsed:.0f}s elapsed", flush=True)
    print(f"predictions written to {out}", flush=True)


if __name__ == "__main__":
    main()
