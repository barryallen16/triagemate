"""Fine-tune LiquidAI/d1-3B on real-world contrastive CVE patch diffs.

Uses 416 real-world balanced Java vulnerability/patch pairs (zero synthetic Juliet).
Evaluates the merged champion model across:
1. GHSA 174 rows (Identity)
2. GHSA 174 rows (Rule Swap Control)
3. Vul4J 14 rows (Identity)

Usage: python d1_contrastive_lora_train.py
"""
import json
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

MODEL = "LiquidAI/d1-3B"
WORK = Path("/content" if Path("/content").exists() else "/tmp")
TRAIN_DATA = WORK / "contrastive_train.jsonl"
OUT_GHSA_IDENTITY = WORK / "d1_lora_identity_ghsa.jsonl"
OUT_GHSA_SWAP = WORK / "d1_lora_swap_ghsa.jsonl"
OUT_VUL4J_IDENTITY = WORK / "d1_lora_identity_vul4j.jsonl"
MERGED_DIR = WORK / "d1_lora_contrastive_merged"

MAX_SEQ = 1536
BATCH = 2
GRAD_ACCUM = 4
EPOCHS = 1
LR = 1e-4

QUESTION = (
    "Is this static-analysis warning a real, exploitable security bug at the flagged sink (marked with >>>) in the code below? "
    "Answer yes only if untrusted input reaches this specific sink without an effective guard."
)
CRITERIA = {
    "true": "Untrusted input reaches the flagged sink marked with '>>>', and no effective validation, escaping, or containment check neutralizes it in the code.",
    "false": "The flagged sink is protected by guards/validation, input is from a trusted or static source, or the pattern is safe or style-only.",
}
QUESTIONS = {"tp": {"type": "noul", "instructions": QUESTION, "criteria": CRITERIA}}


def state_of_annotated(row, window_override=None):
    window = (window_override if window_override is not None else row.get("code_window", ""))[:8000]
    lines = window.splitlines()
    flagged_idx = len(lines) // 2
    annotated = []
    for idx, l in enumerate(lines):
        if idx == flagged_idx:
            annotated.append(f">>> [ALERT LINE {row.get('line', 0)}]: {l}")
        else:
            annotated.append(f"    {l}")
    body = "\n".join(annotated)

    header = [
        f"Rule: {row['rule']}",
        f"CWE: {row['cwe']}",
        f"Severity: {row.get('severity', 'WARNING')}",
        f"File: {str(row['file']).split('/')[-1]}",
        f"Flagged Line: {row.get('line', 0)}",
    ]
    if row.get("message"):
        header.append(f"Rule message: {row['message']}")
    return "\n".join(header) + f"\n\nJava (Flagged sink marked with >>>):\n```java\n{body}\n```"


def build_rule_swap(rows, seed=3407):
    rng = random.Random(seed)
    by_rule = {}
    for i, r in enumerate(rows):
        by_rule.setdefault(r["rule"], []).append(i)
    swapped = [None] * len(rows)
    for rule, indices in by_rule.items():
        if len(indices) == 1:
            swapped[indices[0]] = rows[indices[0]]["code_window"]
        else:
            shuffled = list(indices)
            for _ in range(100):
                rng.shuffle(shuffled)
                if all(a != b for a, b in zip(indices, shuffled)):
                    break
            for orig, new in zip(indices, shuffled):
                swapped[orig] = rows[new]["code_window"]
    return swapped


def score_dataset(model, rows, out_path, window_overrides=None):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    with out_path.open("w", encoding="utf-8") as fh:
        for start in range(0, len(rows), 1):
            chunk = rows[start:start + 1]
            t0 = time.time()
            states = []
            for i, row in enumerate(chunk):
                w_override = window_overrides[start + i] if window_overrides else None
                states.append(state_of_annotated(row, w_override))
            with torch.inference_mode():
                answers = model.system_one_batch([(s, QUESTIONS) for s in states])
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
            done = min(start + 1, len(rows))
            if done % 20 == 0 or done == len(rows):
                print(f"  {done}/{len(rows)}  {time.time() - started:.0f}s", flush=True)
    print(f"predictions written to {out_path}", flush=True)


def main():
    global torch
    import torch
    from datasets import Dataset
    from huggingface_hub import snapshot_download
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModel, AutoModelForImageTextToText, AutoTokenizer
    from trl import SFTConfig, SFTTrainer

    os.environ["WANDB_DISABLED"] = "true"
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

    print(f"1. Downloading model files for {MODEL}...", flush=True)
    local_dir = snapshot_download(MODEL)
    sys.path.insert(0, local_dir)
    from prompt import as_question, render

    tokenizer = AutoTokenizer.from_pretrained(MODEL)
    q = as_question(QUESTIONS["tp"])

    print(f"2. Loading training rows from {TRAIN_DATA}...", flush=True)
    train_rows = [json.loads(l) for l in open(TRAIN_DATA, encoding="utf-8") if l.strip()]
    random.Random(3407).shuffle(train_rows)
    print(f"Loaded {len(train_rows)} contrastive rows", flush=True)

    def fmt(row):
        state_text = state_of_annotated(row)
        prompt = render(tokenizer=tokenizer, state=state_text, q=q, bos=tokenizer.bos_token)
        target = "yes" if row["label"] == "TP" else "no"
        return {"text": prompt + target + tokenizer.eos_token}

    dataset = Dataset.from_list([fmt(r) for r in train_rows])
    print(f"Rendered {len(dataset)} training examples", flush=True)

    print("3. Initializing base model with LoRA...", flush=True)
    base_model = AutoModelForImageTextToText.from_pretrained(
        MODEL,
        torch_dtype=torch.float16,
        device_map="cuda",
        trust_remote_code=True,
    )
    base_model.config.use_cache = False
    base_model.gradient_checkpointing_enable()

    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=r".*language_model.*\.(q_proj|k_proj|v_proj|out_proj)",
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )
    peft_model = get_peft_model(base_model, lora_config)
    peft_model.print_trainable_parameters()

    trainer = SFTTrainer(
        model=peft_model,
        processing_class=tokenizer,
        train_dataset=dataset,
        args=SFTConfig(
            dataset_text_field="text",
            max_length=MAX_SEQ,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=8,
            warmup_steps=10,
            num_train_epochs=EPOCHS,
            learning_rate=LR,
            logging_steps=10,
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            seed=3407,
            output_dir=str(WORK / "lora_checkpoints"),
            report_to="none",
            save_strategy="no",
            fp16=True,
        ),
    )

    print("4. Training Contrastive LoRA on real Java patch diffs...", flush=True)
    t_start = time.time()
    trainer.train()
    print(f"Training completed in {time.time() - t_start:.1f}s!", flush=True)

    print("5. Merging LoRA adapter back into base checkpoint...", flush=True)
    merged_model = peft_model.merge_and_unload()
    merged_model.save_pretrained(str(MERGED_DIR))
    tokenizer.save_pretrained(str(MERGED_DIR))

    for name in ["api.py", "hybrid.py", "lfm2_vl.py", "modeling_d1.py",
                 "prompt.py", "runner.py", "processor_config.json", "LICENSE"]:
        src = os.path.join(local_dir, name)
        if os.path.exists(src):
            shutil.copy(src, MERGED_DIR)
    print(f"Exported merged champion model to {MERGED_DIR}", flush=True)

    del peft_model, base_model, trainer, merged_model
    import gc
    gc.collect()
    torch.cuda.empty_cache()

    print("6. Loading merged champion model for evaluation...", flush=True)
    eval_model = AutoModel.from_pretrained(str(MERGED_DIR), trust_remote_code=True,
                                           torch_dtype=torch.float16).to("cuda")

    import urllib.request
    ghsa_rows = [json.loads(l) for l in urllib.request.urlopen(
        "https://huggingface.co/datasets/barryallen16/triagemate/resolve/main/ghsa-scan-labeled.jsonl"
    ).read().decode().splitlines() if l.strip()]
    vul4j_rows = [json.loads(l) for l in urllib.request.urlopen(
        "https://huggingface.co/datasets/barryallen16/triagemate/resolve/main/vul4j-scan-labeled.jsonl"
    ).read().decode().splitlines() if l.strip()]

    print("\n--- Evaluating Champion: GHSA Identity ---", flush=True)
    score_dataset(eval_model, ghsa_rows, OUT_GHSA_IDENTITY)

    print("\n--- Evaluating Champion: GHSA Rule Swap Control ---", flush=True)
    swapped = build_rule_swap(ghsa_rows)
    score_dataset(eval_model, ghsa_rows, OUT_GHSA_SWAP, window_overrides=swapped)

    print("\n--- Evaluating Champion: Vul4J Identity ---", flush=True)
    score_dataset(eval_model, vul4j_rows, OUT_VUL4J_IDENTITY)

    print("\nAll training and evaluation complete!", flush=True)


if __name__ == "__main__":
    main()
