# The old VulnChecker-Java experiment

This is the pre-pivot README, kept for provenance. The main README explains what replaced it.

Solo fine-tuning experiment: Java vulnerability detection with LoRA-tuned Qwen2.5
models. Dataset curation → synthetic augmentation → dedup → LoRA fine-tuning →
evaluation. This is experiment code with real artifacts, not a production
detector and not a SOTA claim.

**Strongest results:** `barryallen16/Qwen2.5_7B_java_vul_final` scores **979/1000 =
97.90%** on a stratified NIST-Juliet held-out set (`model-evaluation/juliet-heldout-1000.csv`,
Oct 2025 Colab run, per-case file `juliet-final-1000.json`) - with one open flaw:
Juliet method names (`bad`/`good...`) and `POTENTIAL FLAW` comments leak the verdict,
so that run partly measures name-reading. A neutralized re-run on
`juliet-heldout-1000-neutral.csv` (same rows, names and flaw comments scrubbed) is
pending and will replace that number, plus **194/200 =
97.00%** (precision/recall/F1 96.81%) on a 200-case LLM-generated set - see the
stored outputs in `java_eval_new.ipynb`. Two caveats on the 200-case run: the cases
are LLM-written, not a public benchmark, and 31 of the 200 rows are
fix-explanation prose that also appears verbatim in the training set, so they
measure recall rather than detection. On the 169 genuine-Java rows the accuracy
is 96.4-100%.

## Evaluations with saved outputs

These come from stored notebook outputs and per-case files, inspectable
without a GPU.

| Notebook | Model evaluated | Cases | Correct | Accuracy |
|---|---|---|---|---|
| `java_eval_new.ipynb` | `Qwen2.5_7B_java_vul_final` (LoRA on `unsloth/qwen2.5-7b-instruct`, non-Coder) | 200 | 194 | **97.00%** |
| `juliet-final-1000.json` (Colab T4, Oct 2025) | `Qwen2.5_7B_java_vul_final` | 1000 | 979 | 97.90%, confounded - see note |
| `model-evaluation/testcases_java_eval.ipynb` | `Qwen2.5_7B_java_vul_v3` (LoRA on `unsloth/qwen2.5-coder-7b-instruct`) | 88 | 81 | 92.05% |
| `misc/eval-res1.txt` (per-case JSON) | Mistral-Nemo-Instruct-2407 4-bit | 102 | 79 | 77.45% |

Confusion matrix for the 200-case run: 91 TP / 3 FN / 3 FP / 103 TN.

## Older 102-case sweep (weak evidence)

From June-July 2025 notes (`misc/evaulation.md`). Only the Mistral row has a
per-case file; the other three rows were never saved. With n=102 the 95% CI is
roughly ±8 pts, so the 7B-vs-14B gap (2 cases) is noise, not a finding.

| Model | LR | Correct | Accuracy | Per-case file |
|---|---|---|---|---|
| Qwen2.5-Coder 7B | 3e-4 | 82 | 80.39% | none |
| Qwen2.5-Coder 7B (100 max steps) | 2e-4 | 81 | 79.41% | none |
| Qwen2.5-Coder 14B | 2e-4 | 80 | 78.43% | none (weights exist on the Hub) |
| Mistral-Nemo-Instruct-2407 (4-bit) | 2e-4 | 79 | 77.45% | `misc/eval-res1.txt` |

## Pipeline

```
raw datasets -> standardize -> clean -> LLM synthetic augmentation
   -> merge -> sha256 dedup -> preprocess -> conversation-format SFT set
   -> Unsloth LoRA fine-tune -> eval harness
```

- Datasets moved through seven curated stages (~1.1 GB of JSONL), hosted at
  [barryallen16/VulnChecker-Java](https://huggingface.co/datasets/barryallen16/VulnChecker-Java).
  Pull them with `bash scripts/download_data.sh`. Git tracks only stage scripts,
  readmes and notebooks; the JSONL stays out of the repo.
- Deduplication hashes the raw JSON line (`datasets/deduped/`): the merged
  72,271 rows became 67,993, i.e. exactly 4,278 duplicates removed.
- Preprocessing adds parsed structure plus a natural-language hint, then
  `prepare-final-dataset.py` wraps everything in conversation format for
  Unsloth/SFTTrainer.
- Known limitations, measured from the files: `finetuning_dataset_v3.jsonl`
  descends from the *merged* corpus, skipping the dedupe stage (still 7,601
  duplicate rows); the `hint` is built from the ground-truth label and is not
  sent at inference time; `sensitive_api_calls` is never populated (0.00%) and
  `segment_code()` output is unused.
- The eval harness runs a fixed test set against any checkpoint through one
  function call: `evaluate_model(llm_name, test_cases)`.

### Stage sizes

| Stage file | Rows | Labelled VULNERABLE / NOT_VULNERABLE |
|---|---|---|
| `prepared_jsonl/` (8 source files) | 71,363 extracted | mixed, per-source |
| `standarized/` (9 files, incl. `to_join.jsonl`) | 71,078 | mixed, per-source |
| `merged_jsonl/clean_merged.jsonl` | 71,765 | 36,232 / 35,533 |
| `merged_jsonl/clean+enhanced.jsonl` | 72,271 | 36,549 / 35,721 |
| `deduped/deduped_clean_enhance.jsonl` | 67,993 | 33,289 / 34,703 |
| `deduped/final_deduped.jsonl` | 67,571 | 33,054 / 34,517 |
| `preprocess/processed_datasetv1.jsonl` | 71,765 | 36,232 / 35,533 |
| `final-dataset/finetuning_dataset_v3.jsonl` | 71,765 | 36,232 / 35,533 |

`finetuning_dataset_v3.jsonl` - the set behind the currently published adapter -
is built from `processed_datasetv1.jsonl`, which comes from the *merged* corpus.
It therefore skips the synthetic augmentation and the dedupe stage that the two
earlier sets (`previous-versions/`) were built from, and it still carries 7,601
duplicate user turns (one snippet appears 126 times).

### Re-running a stage

The stage scripts were written against the original flat scratch layout, so they
expect to be run from their own directory rather than from the repo root:
`cleaning-code.py` reads `./prepared_jsonl/` and writes `./cleaned/`,
`merge_synthetic.py` reads `./synthetic/`, `dedupe.py` reads
`./cleaned/final-dataset/`, and `prepare-final-dataset.py` reads
`./preprocess/`. Adjust those relative paths before re-running.

## Artifacts

- Fine-tuned weights: [barryallen16/Qwen2.5_7B_java_vul_final](https://huggingface.co/barryallen16/Qwen2.5_7B_java_vul_final)
  (LoRA on `unsloth/qwen2.5-7b-instruct-unsloth-bnb-4bit`, the non-Coder instruct
  model) and the earlier
  [Qwen2.5_7B_java_vul_v3](https://huggingface.co/barryallen16/Qwen2.5_7B_java_vul_v3)
  (LoRA on `unsloth/qwen2.5-coder-7b-instruct-bnb-4bit`).
- Datasets: [HF datasets](https://huggingface.co/datasets/barryallen16/VulnChecker-Java/)
  and the 200-case eval set at
  [java_vulnerability_dataset](https://huggingface.co/datasets/barryallen16/java_vulnerability_dataset).
- The JSONL files are tracked with Git LFS (`.gitattributes`:
  `datasets/**/*.jsonl filter=lfs`), so clone with LFS enabled to get the data.

## Project structure

- `datasets/` - the seven curated stages. Only scripts, readmes and notebooks
  are tracked; stage JSONL is fetched with `bash scripts/download_data.sh`.
  - `prepared_jsonl/` - the eight extracted and initially standardized sources,
    plus `cleaning-code.py`, which applies the final standardization into
    `standarized/`.
  - `standarized/` - all standardized datasets.
  - `synthetic/` - synthetic samples from six LLMs (claude, deepseek, grok,
    llama, mistral, qwen) plus `new_vuls.jsonl`; the generation prompt is in
    the folder's readme.
  - `merged_jsonl/` - `clean_merged.jsonl`, `enhanced_dataset.jsonl`,
    `clean+enhanced.jsonl` and `merge_synthetic.py`; `previous-versions/` keeps
    v1-v3 of the synthetic merge, `merged_output_v4.jsonl` is the final one.
  - `deduped/` - `dedupe.py` plus `deduped_clean_enhance.jsonl` and
    `final_deduped.jsonl`.
  - `preprocess/` - `java-preprocessing-notebook.ipynb` and
    `processed_datasetv1.jsonl`.
  - `final-dataset/` - `prepare-final-dataset.py` and
    `finetuning_dataset_v3.jsonl`; `previous-versions/` holds v1 and v2.
- `finetuning/finetuning_final.ipynb` - LoRA fine-tuning notebook (Unsloth,
  r=64, alpha=16). Note: as committed it loads the 423-record
  `finetuning_dataset_enhanced.jsonl` for 60 steps, not the 71,765-record v3.
- `model-evaluation/` - evaluation notebook plus `testcases-prompt.md`, the
  prompt used to generate the test set from an LLM; `eval-clean-152.csv` (the
  200-case set minus 31 leaked prose rows and 17 training overlaps) and
  `juliet-heldout-1000.csv` (stratified NIST-Juliet sample, seed 42) are the
  frozen sets to re-run everything on.
- `scripts/` - `freeze_eval.py` (rebuilds the clean set), `run_eval.py` (one
  checkpoint × one CSV → per-case JSON, same prompt as the notebooks).
- `java_eval_new.ipynb` - the 200-case evaluation of the published adapter,
  with stored outputs.
- `misc/` - validation scripts (`validate-jsonl-file.py`, `check-datasets.py`,
  `before-tesing.py`), raw test cases (`120-testcases.txt`), the per-case
  Mistral result (`eval-res1.txt`) and the evaluation summary (`evaulation.md`).
- `../all-unorganized-code/` - the original working folders, the project archives
  (`.zip`, `.7z`) and the upstream source corpora, kept for provenance
  (sibling of repo root, outside git).

## The corresponding original dataset links to the files in prepared_jsonl

- java_without_p3.jsonl - https://github.com/rmusab/vul-llm-finetune/blob/main/Datasets/without_p3/java_k_1_strict_2023_07_03.tar.gz
- secure_non_vul.jsonl and secure_vul.jsonl - https://huggingface.co/datasets/CyberNative/Code_Vulnerability_Security_DPO
- code_vul_java.jsonl - https://huggingface.co/datasets/maddyrucos/code_vulnerability_java/ (the folder readme also cites `lemon42-ai/Code_Vulnerability_Labeled_Dataset`)
- prepared_vul4j.jsonl - https://zenodo.org/records/15599983/files/data_VUL4J_patching_Java.csv?download=1
- vul.jsonl and non_vul.jsonl - https://www.kaggle.com/datasets/jiscecseaiml/vulnerability-fix-dataset
- CVEFIXES.jsonl - https://www.kaggle.com/datasets/girish17019/cvefixes-vulnerable-and-fixed-code/data
