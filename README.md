# TriageMate: Static Analysis Alert Triage with Liquid AI d1-3B

Static analysis scanners flag security bugs with high recall, but false-positive rates exceed 70%.
TriageMate uses Liquid AI's hybrid d1-3B to rank alerts by exploitability in under 15 ms, letting developers review real vulnerabilities first.

---

## Quickstart

Run the standalone CLI locally on standard CPU (no GPU required):

```bash
# 1. Interactive demo: path traversal vs guarded XML parser
python d1_triage.py --demo

# 2. Triage a Semgrep report and export prioritized JSON
python d1_triage.py --scan semgrep-findings.json --output triage-report.json

# 3. Sample 5 benchmark alerts
python d1_triage.py --benchmark ghsa --limit 5
```

Add `--mock` to any command for a dry run without downloading model weights.

---

## Benchmark Leaderboard

Evaluated on 174 real-world Java alerts from 68 GitHub advisories (GHSA) and all 126 Vul4J benchmark repositories.

| Model / Configuration | Architecture | Ground Truth AUC (L3) | Within-Rule AUC (L3) | Rule-Swap Delta | Vul4J Real CVEs | Latency / Hardware |
|---|---|---|---|---|---|---|
| **Heuristic Baseline** | Scanner rules | 0.5235 | 0.5000 | N/A | 0.5778 | <1 ms (CPU) |
| **Kev-4B** | 4B Transformer | 0.7167 | 0.5100 | +0.0180 | 0.6667 | ~85 ms / 12.8 GB VRAM |
| **d1-3B Zero-Shot** | 3B Hybrid SSM | **0.8372** | 0.5495 | +0.0202 | **0.8000** | 12 ms / 6.2 GB VRAM |
| **d1-3B Targeted Prompt** | 3B Hybrid SSM | 0.6261 | 0.5761 | +0.0749 | **0.8000** | 12 ms / 6.2 GB VRAM |
| **d1-3B Contrastive LoRA** | 3B Hybrid SSM | 0.5988 | **0.6594** | **+0.0839** | 0.5444 | 14 ms / 6.3 GB VRAM |
| **d1-3B 50/50 Ensemble** | 3B Hybrid SSM | 0.6125 | **0.6280** | +0.0794 | **0.8000** | 25 ms / 6.3 GB VRAM |

*Definitions*: **L3**: Finding line sits inside verified fix hunk and matches CVE CWE. **Within-Rule AUC**: Discrimination among alerts from the same rule family. **Swap Delta**: Drop in AUC when swapping code behind identical rules. Full 4-level gate matrix in [audit/TECHNICAL_REPORT.md](audit/TECHNICAL_REPORT.md).

---

## Core Findings

- **Statement Anchoring Fixes Within-Rule Blindness**: Scanners report 1-based file lines, but LLMs receive unnumbered method snippets. Injecting `>>> [ALERT LINE X]` restored code sensitivity, lifting within-rule AUC from 0.4297 to 0.5986.
- **Real-World Contrastive Tuning Stops Synthetic Collapse**: Training on synthetic Juliet test cases degraded real-world transfer. Fine-tuning on 416 real pre- and post-fix commit diffs achieved 0.6594 within-rule AUC on verified fix hunks.
- **Linear Efficiency Beats 4B Dense Models**: On verified fix hunks (L3), d1-3B scores 0.8372 AUC vs Kev-4B's 0.7167 (+12.05%). It runs in 12-14 ms on an Nvidia T4 with half the VRAM (6.2 GiB vs 12.8 GiB).

---

## One-Command Reproduction

Calculate all metrics on CPU in under 0.2 seconds:

```bash
python audit/evaluate_d1.py
```

Run the 19-test verification suite:

```bash
python audit/test_whole_suite.py
```

---

## Published Artifacts

- **Model Weights**: [barryallen16/d1-3B-java-vuln-triage](https://huggingface.co/barryallen16/d1-3B-java-vuln-triage)
- **Benchmark Dataset**: [barryallen16/triagemate](https://huggingface.co/datasets/barryallen16/triagemate)
- **Technical Report**: [audit/TECHNICAL_REPORT.md](audit/TECHNICAL_REPORT.md) (proofs, rule priors, and confidence intervals)
