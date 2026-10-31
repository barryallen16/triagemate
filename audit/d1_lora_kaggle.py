"""d1-3B LoRA on synthetic TriageMate rows, evaluated on the 174-row real set.

Follows the Liquid cookbook SFT recipe: FastVisionModel, LoRA r=16 alpha=32,
language-model modules only, 1 epoch, lr 2e-4, merge to 16-bit, copy d1's
System One code back, then score the real rows.

Pilot uses a balanced 3,000-row sample of the 7,797-row train split and
max_seq_length 1536 so it finishes on a T4 under a tight budget.

Usage on Kaggle: python d1_lora_kaggle.py
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

MODEL = "LiquidAI/d1-3B"
DATA_URL = os.environ.get(
    "TRIGEMATE_TRAIN_URL",
    "https://huggingface.co/datasets/barryallen16/triagemate/"
    "resolve/main/triage-v1.tar.gz")
EVAL_URL = os.environ.get(
    "TRIGEMATE_EVAL_URL",
    "https://huggingface.co/datasets/barryallen16/triagemate/"
    "resolve/main/ghsa-scan-labeled.jsonl")
WORK = Path("/kaggle/working")
if not WORK.exists():
    WORK = Path("/tmp")
TRAIN_ROWS = 3000
MAX_SEQ = 1536
MAX_CHARS = 8000
BATCH = 2
GRAD_ACCUM = 8

QUESTION = ("Is this static-analysis warning a real, exploitable security bug "
            "in the code below? Answer yes only if the vulnerable pattern is "
            "present and reachable in this code.")
CRITERIA = {
    "true": "The code contains the unsafe pattern named by the rule, and "
            "untrusted input can reach it without an effective guard.",
    "false": "The pattern is absent or neutralized, or the code is unreachable "
             "from untrusted input, or the alert is style-only.",
}
QUESTIONS = {"tp": {"type": "noul", "instructions": QUESTION,
                    "criteria": CRITERIA}}


def state_of(row):
    """Same state text as the inference scorers, with safe defaults for synthetic rows."""
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


def fetch_training_rows():
    dest = WORK / "triage-data"
    dest.mkdir(parents=True, exist_ok=True)
    tgz = dest / "triage-v1.tar.gz"
    if not tgz.exists():
        urllib.request.urlretrieve(DATA_URL, tgz)
    with tarfile.open(tgz) as t:
        t.extractall(dest)
    rows = [json.loads(line) for line in
            open(dest / "triage_train.jsonl", encoding="utf-8")]
    rng = random.Random(3407)
    tp = [r for r in rows if r["label"] == "TP"]
    fp = [r for r in rows if r["label"] == "FP"]
    n = TRAIN_ROWS // 2
    sample = rng.sample(tp, min(n, len(tp))) + rng.sample(fp, min(n, len(fp)))
    rng.shuffle(sample)
    print(f"train pool {len(rows)}, sample {len(sample)} "
          f"({sum(r['label'] == 'TP' for r in sample)} TP)", flush=True)
    return sample


def main():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "unsloth"])
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "transformers==5.17.0", "torchao>0.16.0"])
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "--no-deps", "trl==1.15.0"])

    from unsloth import FastVisionModel
    from unsloth.chat_templates import train_on_responses_only
    import torch
    from datasets import Dataset
    from huggingface_hub import snapshot_download
    from transformers import AutoModel, AutoModelForImageTextToText, AutoTokenizer
    from trl import SFTConfig, SFTTrainer

    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
    os.environ["WANDB_DISABLED"] = "true"
    local_dir = snapshot_download(MODEL)
    sys.path.insert(0, local_dir)
    from prompt import as_question, render

    tokenizer = AutoTokenizer.from_pretrained(MODEL)
    q = as_question(QUESTIONS["tp"])
    rows = fetch_training_rows()

    def fmt(row):
        prompt = render(tokenizer=tokenizer, state=state_of(row), q=q,
                        bos=tokenizer.bos_token)
        answer = "yes" if row["label"] == "TP" else "no"
        return {"text": prompt + answer + tokenizer.eos_token}

    dataset = Dataset.from_list([fmt(r) for r in rows])
    print(f"rendered {len(dataset)} rows, first prompt chars {len(dataset[0]['text'])}",
          flush=True)

    model, _ = FastVisionModel.from_pretrained(
        model_name=MODEL,
        auto_model=AutoModelForImageTextToText,
        max_seq_length=MAX_SEQ,
        load_in_4bit=False,
    )
    model = FastVisionModel.get_peft_model(
        model,
        r=16,
        target_modules=r".*language_model.*\.(q_proj|k_proj|v_proj|out_proj|in_proj|w1|w2|w3)",
        lora_alpha=32,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=3407,
        use_rslora=False,
        loftq_config=None,
    )
    FastVisionModel.for_training(model)

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        args=SFTConfig(
            dataset_text_field="text",
            per_device_train_batch_size=BATCH,
            gradient_accumulation_steps=GRAD_ACCUM,
            warmup_steps=0.05,
            num_train_epochs=1,
            learning_rate=2e-4,
            logging_steps=10,
            optim="adamw_8bit",
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            seed=3407,
            output_dir=str(WORK / "d1_lora_out"),
            report_to="none",
            save_strategy="no",
        ),
    )
    trainer = train_on_responses_only(
        trainer,
        instruction_part="<|im_start|>user\n",
        response_part="<|im_start|>assistant\n",
    )
    started = time.time()
    stats = trainer.train()
    print(f"train_runtime {stats.metrics.get('train_runtime')}s "
          f"wall {time.time() - started:.0f}s", flush=True)

    merged = WORK / "d1_lora_merged"
    model.save_pretrained_merged(str(merged), tokenizer, save_method="merged_16bit")
    for name in ["api.py", "hybrid.py", "lfm2_vl.py", "modeling_d1.py",
                 "prompt.py", "runner.py", "processor_config.json", "LICENSE"]:
        shutil.copy(os.path.join(local_dir, name), merged)
    print(f"merged model at {merged}", flush=True)

    del model, trainer
    import gc
    gc.collect()
    torch.cuda.empty_cache()

    eval_rows = [json.loads(line) for line in
                 urllib.request.urlopen(EVAL_URL, timeout=120).read().decode().splitlines()
                 if line.strip()]
    print(f"scoring {len(eval_rows)} real rows", flush=True)
    model = AutoModel.from_pretrained(str(merged), trust_remote_code=True,
                                      dtype=torch.float16).to("cuda")
    out = WORK / "d1_lora_ghsa.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for i, row in enumerate(eval_rows, 1):
            t0 = time.time()
            answer = model.system_one(state_of(row), QUESTIONS)
            p_tp = float(answer["answers"]["tp"]["noul"])
            fh.write(json.dumps({
                "id": row["id"],
                "label": row["label"],
                "p_tp": p_tp,
                "confidence": round(max(p_tp, 1.0 - p_tp), 6),
                "seconds": round(time.time() - t0, 3),
            }) + "\n")
            if i % 10 == 0 or i == len(eval_rows):
                print(f"  {i}/{len(eval_rows)}", flush=True)
    print(f"predictions written to {out}", flush=True)


if __name__ == "__main__":
    main()
