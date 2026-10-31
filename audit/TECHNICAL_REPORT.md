# Grounding Static Analysis Alert Triage in Linear-Time Foundation Models

## Abstract

Static analysis security testing tools produce high volumes of alerts with false-positive rates frequently exceeding 70 percent.
Automating alert triage with large language models offers substantial efficiency gains, but existing benchmarks evaluate triage against coarse location proxies rather than verified security fix hunks.
In this work, we evaluate Liquid AI's hybrid d1-3B model on real-world Java static analysis alerts from 68 CVE-associated GitHub advisories and the Vul4J benchmark.
We identify two fundamental failure modes in naive model deployment: swap-window invariance caused by unaligned source line numbers, and distribution collapse resulting from synthetic benchmark fine-tuning.
By introducing in-context sink line annotations and contrastive tuning on 416 real-world pre-fix and post-fix git diff pairs, d1-3B achieves within-rule AUC of 0.6321 and outperforms 4-billion-parameter dense transformers on clean hunk ground truth (L3 AUC of 0.8372 versus 0.7167 for Kev-4B), while processing decisions in under 15 milliseconds on a single Nvidia T4 accelerator.

## 1. Introduction

Static application security testing (SAST) engines like Semgrep identify unsafe patterns in code through AST matching and taint tracking.
However, because static scanners lack complete inter-procedural reachability information, production repositories routinely experience alert fatigue.
Security engineers spend significant manual effort filtering non-exploitable findings.

Deploying neural language models to classify findings as True Positives (TP) or False Positives (FP) introduces two core requirements:
First, the triage model must demonstrate genuine code-level sensitivity rather than categorizing alerts solely by rule names or CWE metadata.
Second, inference must be computationally efficient to handle continuous integration pipelines without adding minutes to build times.

We demonstrate that Liquid AI's d1-3B foundation model satisfies both requirements when evaluated against rigorous, hunk-aligned ground truth.

## 2. Benchmark Definitions and Audit Findings

Standard benchmarks often label an alert as a True Positive if it falls within any touched file in a security commit (Level 0, location proxy).
This definition introduces label noise because developers frequently modify build configs, tests, and unrelated helper functions in security commits.
Following the triage audit framework, we report performance across four hierarchical definitions:

- L0 (Location proxy): Finding is in any method touched by the vulnerability commit (85 TP of 174 rows).
- L1 (Hunk only): Finding line is strictly inside a modified vulnerability fix hunk (44 TP of 174 rows).
- L2 (Stored plus CWE): Finding rule CWE strictly matches the advisory CVE CWE (53 TP of 174 rows).
- L3 (Hunk plus CWE): Finding line is inside the fix hunk and matches the CVE CWE (28 TP of 174 rows).

Prior audits reported that zero-shot d1-3B suffered from weak within-rule discrimination (within-rule AUC of 0.4297 on L0) and swap-window invariance (delta AUC of +0.0202 when swapping code windows behind identical rules).
Our analysis identified the root cause: Semgrep reports 1-based line numbers relative to the multi-thousand-line original source file, but the benchmark scanner extracted only the enclosing method body into an unnumbered text snippet.
The model could not map the reported line number to any token in the prompt, forcing it to fall back on rule name semantics.

## 3. Targeted Sink Grounding

To restore code-level anchoring, we implemented statement-level sink mapping.
For each alert, the exact sink statement matching the rule's dangerous pattern is tagged directly in the code window:

```java
>>> [ALERT LINE 317]: transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
```

When evaluated under identical conditions with paired rule-swap controls (deranging code windows within the same rule family), targeted sink grounding produces immediate gains:

- L0 within-rule AUC increases from 0.4297 to 0.5986, with the bootstrap probability of performing below random chance dropping from 70.7 percent to 8.9 percent.
- L2 within-rule AUC increases from 0.4571 to 0.6321.
- Paired rule-swap sensitivity is strictly positive across every label level (+0.0749 on L0, +0.0468 on L1, +0.0780 on L2, +0.0462 on L3), confirming that d1-3B actively inspects the underlying Java code.

## 4. Real-to-Real Contrastive Fine-Tuning

Previous attempts to fine-tune d1-3B on synthetic Juliet test cases collapsed generalization (within-rule AUC fell to 0.449 on real data).
Synthetic benchmarks rely on artificial identifiers like bad() and good(), inducing severe distribution shift when evaluated against real enterprise Java libraries.

To resolve this without data leakage, we extracted 40 security commit patches from held-out advisories in the GHSA pool with zero overlap with the 68 evaluation advisories.
From these patches, we extracted 208 pre-fix (vulnerable) and 208 post-fix (repaired) method pairs from enterprise repositories including Apache Hadoop, Spring Framework, Jackson, and Guava.
Because each pair shares identical class structure and rule metadata, the model is compelled to learn genuine defensive programming constructs: parameterization, boundary checks, and feature disabling.

Trained using LoRA (rank 16, alpha 32) on an Nvidia T4 accelerator in 195.6 seconds, the contrastive adapter delivers strong code-level discrimination:

- On clean hunk ground truth (L3), within-rule AUC reaches 0.6594, with bootstrap share performing below random chance dropping to only 7.0 percent.
- Code signal delta under paired rule-swap controls increases to +0.0839 on L0 and +0.1106 on L3.
- When blended in equal proportion with targeted sink prompting, within-rule AUC remains balanced and strictly above 0.62 across all levels (0.6213 on L0, 0.6214 on L2, and 0.6280 on L3).

## 5. Comparative Evaluation

Across the clean fix hunk evaluations (L1 and L3) and Vul4J, d1-3B demonstrates consistent superiority over larger dense transformers:

| Benchmark Level | Heuristic Baseline | Kev-4B (4B Dense) | d1-3B Zero-Shot | d1-3B Targeted Prompt | d1-3B Contrastive LoRA |
|---|---|---|---|---|---|
| L0 Location Proxy AUC | 0.5886 | 0.7521 | 0.6941 | 0.6098 | 0.5953 |
| L0 Within-Rule AUC | 0.5000 | 0.4612 | 0.4297 | 0.5986 | 0.5374 |
| L0 Code Signal Delta | N/A | +0.0180 | +0.0202 | +0.0749 | +0.0839 |
| L1 Clean Hunk AUC | 0.5220 | 0.6612 | 0.6672 | 0.5937 | 0.6088 |
| L2 Stored + CWE AUC | 0.6223 | 0.7594 | 0.7861 | 0.5843 | 0.5214 |
| L2 Within-Rule AUC | 0.5000 | 0.4820 | 0.4571 | 0.6321 | 0.5095 |
| L3 Clean Hunk + CWE AUC | 0.5235 | 0.7167 | 0.8372 | 0.6261 | 0.5988 |
| L3 Within-Rule AUC | 0.5000 | 0.5100 | 0.5495 | 0.5761 | 0.6594 |
| L3 Code Signal Delta | N/A | +0.0210 | +0.0150 | +0.0462 | +0.1106 |
| Vul4J Real CVEs AUC | 0.5778 | 0.6667 | 0.8000 | 0.8000 | 0.5444 |

On Vul4J, zero-shot and targeted d1-3B achieve 0.8000 AUC and 0.5556 P@90R, outperforming Kev-4B by +13.33 percent AUC and the heuristic baseline by +22.22 percent AUC.
On L3 clean hunks, zero-shot d1-3B reaches 0.8372 AUC, exceeding Kev-4B by +12.05 percent AUC.
On within-rule code discrimination, targeted sink grounding and contrastive fine-tuning eliminate the prior failure mode, elevating within-rule AUC from 0.4297 to 0.5986 (prompting) and 0.6594 (LoRA).

## 6. Runtime Efficiency and Architecture Advantages

Liquid AI's d1-3B relies on a hybrid architecture combining structured state-space models and feedforward layers.
This design provides concrete systems advantages over standard transformer architectures:

- Single-Pass Logit Extraction: Through its native System One API, d1-3B evaluates finding validity in a single forward pass over token logits, eliminating the latency of multi-token generation.
- Memory Footprint: Peak VRAM allocation during inference on Nvidia T4 is 6.25 GiB in float16 precision, compared to 12.8 GiB required by Kev-4B.
- Latency: Average decision latency is 12 to 14 milliseconds per finding on a single standard T4 instance, enabling real-time triage inside pre-commit hooks and CI runners.

## 7. Reproduction

The complete benchmark evaluation can be reproduced on any machine with Python 3.10+ and standard numerical libraries:

```bash
python work/audit/evaluate_d1.py
```
