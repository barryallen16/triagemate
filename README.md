# TriageMate: Static Analysis Alert Triage with Liquid AI d1-3B

Static analysis tools like Semgrep find candidate vulnerabilities with high recall, but false positive rates often exceed 70 percent.
TriageMate ranks these alerts by exploitability so security teams and developers can review real bugs first.
The primary model is Liquid AI's hybrid d1-3B, running single-pass logit classification on consumer CPUs and GPUs.

---

## Benchmark Leaderboard

Evaluated on 174 real-world Java security alerts from 68 GitHub advisories (GHSA) across four ground-truth definitions, plus the complete population of Semgrep security findings across all 126 repositories in the Vul4J benchmark.

| Model / Configuration | Architecture | L0 Location Proxy AUC | L0 Within-Rule AUC | L0 Swap Delta | L2 Stored + CWE AUC | L2 Within-Rule AUC | L3 Clean Hunk + CWE AUC | L3 Within-Rule AUC | Vul4J Real CVEs AUC |
|---|---|---|---|---|---|---|---|---|---|
| **Heuristic Baseline** | Scanner rules | 0.5886 | 0.5000 | N/A | 0.6223 | 0.5000 | 0.5235 | 0.5000 | 0.5778 |
| **Kev-4B** | 4B Dense Transformer | 0.7521 | 0.4612 | +0.0180 | 0.7594 | 0.4820 | 0.7167 | 0.5100 | 0.6667 |
| **d1-3B Zero-Shot (Audit)** | 3B Hybrid SSM | 0.6941 | 0.4297 | +0.0202 | 0.7861 | 0.4571 | **0.8372** | 0.5495 | **0.8000** |
| **d1-3B Targeted Prompt** | 3B Hybrid SSM | 0.6098 | **0.5986** | +0.0749 | 0.5843 | **0.6321** | 0.6261 | 0.5761 | **0.8000** |
| **d1-3B Contrastive LoRA** | 3B Hybrid SSM | 0.5953 | 0.5374 | **+0.0839** | 0.5214 | 0.5095 | 0.5988 | **0.6594** | 0.5444 |
| **d1-3B 50/50 Ensemble** | 3B Hybrid SSM | 0.6227 | **0.6213** | +0.0794 | 0.5682 | **0.6214** | 0.6125 | **0.6280** | **0.8000** |

### Benchmark Definitions

- **L0 (Location Proxy)**: Finding is located anywhere in a method modified by the vulnerability commit (85 TP of 174 rows).
- **L1 (Clean Hunk Only)**: Finding line sits strictly inside a modified vulnerability fix hunk (44 TP of 174 rows).
- **L2 (Stored plus CWE)**: Finding rule CWE strictly matches the advisory CVE CWE (53 TP of 174 rows).
- **L3 (Clean Hunk plus CWE)**: Finding line is inside the fix hunk and matches the CVE CWE (28 TP of 174 rows).
- **Within-Rule AUC**: Model discrimination measured strictly among alerts flagged by the exact same Semgrep rule family.
- **Swap Delta**: Drop in AUC when the code window behind a rule is swapped with another code window from the same rule family.
- **Vul4J Benchmark**: Complete census of all Semgrep security findings across changed files in all 126 Vul4J benchmark repositories (5 TP, 9 FP across 10 distinct CVEs).

---

## Technical Summary

### 1. Fixing the Within-Rule Bottleneck

The initial audit found that zero-shot d1-3B scored 0.4297 on L0 within-rule AUC, performing below random chance inside rule families.
The cause was an unaligned line number.
Semgrep reported line numbers based on the full multi-thousand-line source file, but the triage harness extracted only the enclosing method body as an unnumbered snippet.
The model could not link the reported line number to any token in the prompt, so it fell back on rule-name semantics.

Marking the dangerous statement directly in the prompt restored code-level anchoring:

```java
>>> [ALERT LINE 45]: File targetFile = new File(baseDir, userReportName);
```

Under this prompt format, L0 within-rule AUC increased from 0.4297 to 0.5986, and L2 within-rule AUC increased from 0.4571 to 0.6321.
The bootstrap share of runs performing at or below 0.5 dropped from 70.7 percent to 8.9 percent.
Paired rule-swap delta became positive across every definition (+0.0749 on L0, +0.0780 on L2).

### 2. Leak-Free Real-to-Real Contrastive Fine-Tuning

Earlier fine-tuning experiments used synthetic Juliet test cases, which caused distribution shift and lowered real-world AUC to 0.59.
To avoid synthetic identifiers and prevent test set leakage, we extracted 40 security commit diffs from held-out advisories in the GHSA pool with zero overlap with the 68 evaluation advisories.
From these patches, we extracted 208 pre-fix and 208 post-fix method pairs from enterprise Java repositories including Apache Hadoop, Spring Framework, Jackson, and Guava.

Trained using LoRA (rank 16, alpha 32) on an Nvidia T4 GPU in 195.6 seconds, the contrastive adapter reached 0.6594 within-rule AUC on verified security fix hunks (L3).
Code signal delta under paired rule-swap controls reached +0.1106 on L3.
A 50/50 blend of targeted prompting and contrastive LoRA maintains within-rule AUC above 0.62 across all levels (0.6213 on L0, 0.6214 on L2, and 0.6280 on L3).

### 3. Comparison with 4B Dense Transformers

On verified security fix hunks (L3), d1-3B reaches 0.8372 AUC, compared to Kev-4B's 0.7167 (+12.05% margin).
On the Vul4J benchmark, d1-3B reaches 0.8000 AUC and 0.5556 P@90R, compared to Kev-4B's 0.6667 (+13.33% margin).
Inference latency on an Nvidia T4 accelerator is 12 to 14 milliseconds per finding using d1's native single-pass System One logit extraction, with peak VRAM consumption of 6.25 GiB (versus 12.8 GiB for Kev-4B).

---

## Quickstart: Local CLI (`d1-triage`)

The repository includes a standalone triage tool that runs on standard CPUs without an Nvidia GPU:

### 1. Interactive Demonstration

Run a showcase comparison between a real path traversal vulnerability and a guarded XML parser false alarm:

```bash
python d1_triage.py --demo
```

### 2. Triage a Semgrep Scan Report

Run Semgrep on your repository and pipe the JSON output directly to `d1-triage`:

```bash
semgrep scan --config auto --json -o semgrep-findings.json
python d1_triage.py --scan semgrep-findings.json --output triage-report.json
```

### 3. Sample Benchmark Alerts

Triage alerts directly from the evaluation benchmark:

```bash
python d1_triage.py --benchmark ghsa --limit 5
python d1_triage.py --benchmark vul4j --limit 5
```

Add `--mock` to any command for a dry-run without downloading model weights.

---

## Reproduction and Testing

### One-Command Benchmark Reproduction

Calculate all L0 to L3 gate metrics, paired rule-swap deltas, and Vul4J results locally on CPU in under 0.2 seconds:

```bash
python audit/evaluate_d1.py
```

### End-to-End Test Suite

Run the 19-test verification suite covering dataset integrity, leakage safeguards, prediction files, sink finder logic, and CLI commands:

```bash
python audit/test_whole_suite.py
```

---

## Repository Structure

```
├── README.md                      # Primary project documentation
├── d1_triage.py                   # Root launcher for the local triage CLI
├── d1_triage/                     # Standalone CLI package
│   ├── cli.py                     # Argument parsing and scan ingestion
│   ├── engine.py                  # D1 triage engine with 2-stage explanation logic
│   ├── formatters.py              # Rich terminal reporting and JSON export
│   └── sink_finder.py             # Statement-level sink locator regex patterns
├── audit/                         # Benchmark evaluation and training artifacts
│   ├── evaluate_d1.py             # Zero-dependency benchmark evaluation harness
│   ├── compare_all_phases.py      # Cross-phase empirical comparison script
│   ├── test_whole_suite.py        # 19-test verification suite
│   ├── TECHNICAL_REPORT.md        # Full academic technical report
│   ├── contrastive_train.jsonl    # 416 balanced real-to-real training pairs
│   └── d1_contrastive_lora_train.py # LoRA training script for Colab / T4
├── data/                          # Benchmark datasets
│   ├── ghsa-eval/                 # 174 labeled GHSA alerts from 68 advisories
│   └── vul4j-eval/                # 14 changed-file alerts from 126 Vul4J repos
├── docs/                          # Dataset documentation and cards
├── notes/                         # Security and build audit notes
├── scripts/                       # Scan and evaluation automation scripts
└── triage/                        # Core triage decision engine
```

---

## Published Artifacts

- **Hugging Face Model Hub**: [barryallen16/d1-3B-java-vuln-triage](https://huggingface.co/barryallen16/d1-3B-java-vuln-triage)
- **Hugging Face Dataset**: [barryallen16/triagemate](https://huggingface.co/datasets/barryallen16/triagemate)
