# d1-triage: Local Static Analysis Alert Triage CLI

`d1-triage` is a standalone developer tool powered by Liquid AI's `d1-3B` foundation model.
It automates the triage of static application security testing (SAST) warnings directly on developer laptops and CI runners.

## Highlights

- CPU and GPU Native: Executes on standard multi-core CPUs in 1 to 2 seconds per alert without requiring an Nvidia GPU.
- Statement-Level Sink Grounding: Automatically identifies the exact dangerous statement flagged by static scanners.
- Semgrep Native: Ingests standard Semgrep JSON scan reports directly.
- Noise Reduction: Filters non-exploitable patterns and guards to reduce developer alert fatigue.

## Quick Start

### 1. Interactive Demo Showcase
Run the built-in demonstration showcasing real-world True Positive versus False Positive triage:

```bash
python d1_triage.py --demo
```

### 2. Triage a Semgrep Scan Report
Scan your project with Semgrep and pass the JSON output directly to `d1-triage`:

```bash
semgrep scan --config auto --json -o semgrep-report.json
python d1_triage.py --scan semgrep-report.json --output triage-summary.json
```

### 3. Triage Benchmark Findings
Evaluate alerts directly from the GHSA or Vul4J benchmark sets:

```bash
python d1_triage.py --benchmark ghsa --limit 5
python d1_triage.py --benchmark vul4j --limit 5
```

### 4. Fast Integration Dry-Run
Test pipeline parsing and report generation without downloading model weights:

```bash
python d1_triage.py --demo --mock
```

## CLI Reference

| Flag | Description | Default |
|---|---|---|
| `--demo` | Run interactive demonstration on two contrasting findings | False |
| `--scan <path>` | Path to Semgrep JSON scan report | None |
| `--benchmark <name>` | Sample findings from `ghsa` or `vul4j` benchmark | None |
| `--limit <n>` | Number of benchmark findings to analyze | 5 |
| `--cpu` | Force CPU execution | Auto-detect |
| `--gpu` | Force CUDA execution | Auto-detect |
| `--mock` | Fast dry-run without loading model weights | False |
| `--threshold <f>` | Exploitability decision threshold | 0.5 |
| `--output <path>` | Export structured results to JSON | None |
| `--model <id>` | Hugging Face model repository or local directory | LiquidAI/d1-3B |
