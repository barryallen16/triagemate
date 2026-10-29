# A3: Vul4J live-repo scans

The A3 scanner checks out each entry at the parent of its fix commit, runs Semgrep on the files the fix touches, and stores scans and finding rows under `data/vul4j-eval/`.
Findings inside test sources are dropped: Vul4J patches usually add a regression test next to the fix, and a rule hit there would be labeled TP for overlap alone.

## Scan scope

The first pass covered the entries from the A1 build audit that also built and matched a target CWE.
That set was small and mixed full-repository scans with changed-file scans, which made the label set inconsistent.
The current pass covers every entry in `benchmarks/vul4j/dataset/vul4j_dataset.csv` that has a usable patch commit:

```bash
uv run python scripts/vul4j_scan.py --all-vul4j --all-cwes --changed-only --force --timeout 600
```

- 126 of 127 entries scanned.
  VUL4J-23 fails because its patch commit is no longer reachable in `apache/sling`.
- VUL4J-27 and VUL4J-28 have a GitHub `compare` URL instead of a commit, so `load_all_entries` skips them.
- No build is required to scan, so `--all-vul4j` does not claim the entries build.
  Build status is recorded separately in `data/vul4j-audit/audit_report.jsonl`.
- The run took about 1.5 hours on this 2 CPU VPS, mostly clone time.

`--changed-only` runs `p/security-audit` and `p/owasp-top-ten` on the changed Java files, so the scan sees the same file set the label rule can match.
Whole-repository runs took 22 minutes on Batik alone; changed-file runs take 30 seconds to 3 minutes per entry.

## Label set

A finding is labeled TP when its reported line overlaps a line changed by the fix, including two lines of context, or falls inside a method the fix changes.
CWE metadata is saved for analysis but does not decide the label.
This is a proxy for the vulnerability location: a patch may change nearby code for another reason, and a vulnerability may involve code the patch did not touch.

The current set is 14 findings from 10 entries: 5 TP and 9 FP.
The severity heuristic scores ROC-AUC 0.5778 and precision at 90% recall 0.3571 on these rows.
That clears the gate's eight-entry minimum.

Per entry:

| Entry | TP | FP |
|---|---|---|
| VUL4J-3 | 1 | 0 |
| VUL4J-19 | 0 | 2 |
| VUL4J-37 | 0 | 1 |
| VUL4J-38 | 0 | 1 |
| VUL4J-45 | 1 | 0 |
| VUL4J-61 | 1 | 1 |
| VUL4J-65 | 0 | 2 |
| VUL4J-83-S | 1 | 0 |
| VUL4J-92-S | 0 | 2 |
| VUL4J-107-S | 1 | 0 |

The scan produced 36 findings before filtering.
The 22 rows dropped came from VUL4J-10, VUL4J-21 and VUL4J-34, whose only hits sat in `src/test/java`.

## Human check of the five positives

Each positive was compared against the upstream patch.

| Entry | Represented by | Patch does |
|---|---|---|
| VUL4J-3 | `camel-core/.../jaxp/XmlConverter.java:601`, XXE on a SAX parser | disables external general entities on the `SAXParserFactory` at that line |
| VUL4J-45 | `esigate-core/.../xml/XsltRenderer.java:91`, transformer factory without DTD protection | sets `FEATURE_SECURE_PROCESSING` on the transformer factory at that line |
| VUL4J-61 | `src/main/java/apoc/load/Xml.java:68`, DocumentBuilderFactory XXE | sets `disallow-doctype-decl` on the document builder at that line |
| VUL4J-83-S | `hbase-server/.../http/jmx/JMXJsonServlet.java:170`, unescaped servlet writer | wraps the JSONP callback in `ESAPI.encoder().encodeForJavaScript` at that line |
| VUL4J-107-S | `src/main/java/net/fs/server/MapTunnelProcessor.java:74`, plain `Socket` | only renames constants (`code_success` to `CODE_SUCCESS`); not a security fix |

So four of the five positives are genuine security fixes at the flagged line.
VUL4J-107-S is a code-style refactor (S1444, `public static` fields should be constant) that happens to touch the flagged line.
The mechanical label rule counts it as TP because the line changed.
Dropping that entry leaves 13 rows and 4 TP, and the numbers below still hold with a smaller margin.

The older 66-row `labeled.jsonl` uses a different label rule (rule CWE matches the entry CWE) and is not merged into this set.

## Why the earlier 46-row result was misleading

The previous set mixed full-repository scans with changed-file scans.
36 of its 46 rows were findings in files the fix never touched, which cannot be positive by the location rule, so the set was mostly free negatives.
That inflated every scorer's AUC, including d1's 0.9091.
The current set has no such rows: every row has `changed_file` true.

## Gate result on LiquidAI d1-3B

`LiquidAI/d1-3B` is a public 3.12B decision model that answers a typed yes/no question with a calibrated P(yes) in one forward pass.
It scored all 14 rows on one Kaggle T4 with `worktrees/decision-scorer/scripts/d1_kaggle.py`.

| Scorer | n | ROC-AUC | Precision at 90% recall | Delta AUC |
|---|---|---|---|---|
| Semgrep severity heuristic | 14 | 0.5778 | 0.3571 | - |
| LiquidAI d1-3B | 14 | 0.8000 | 0.5556 | +0.2222 |

The gate passes: +0.2222 ROC-AUC and +0.1985 precision at 90% recall.

Robustness checks:

- A row bootstrap gives a 95% interval for the delta of -0.1250 to +0.5503, with P(delta <= 0) of 0.094.
- An entry-level cluster bootstrap gives -0.1002 to +0.5294, with P(delta <= 0) of 0.095.
- Leave-one-entry-out never drops below +0.1250.
- Without the style-refactor entry VUL4J-107-S the delta is still +0.1250 (heuristic 0.6528, d1 0.7778).

This is a stronger result than the earlier 46-row pass: the margin is about ten times larger, and no single entry carries it.

## Gate result on Kev-4B

`jaredpalmer/kev-4b` is a 4B LoRA decision model served through its own repo loader.
`worktrees/decision-scorer/scripts/kev_kaggle.py` installs the repo, drops the incompatible `torchao` build that Kaggle ships, and answers the same yes/no question.

| Scorer | n | ROC-AUC | Precision at 90% recall | Delta AUC |
|---|---|---|---|---|
| Semgrep severity heuristic | 14 | 0.5778 | 0.3571 | - |
| Kev-4B | 14 | 0.6667 | 0.4545 | +0.0889 |

The gate passes on the letter of the rule, but the result is not robust:

- A row bootstrap gives -0.4583 to +0.6000, with P(delta <= 0) of 0.350.
- Dropping VUL4J-65, VUL4J-83-S or VUL4J-107-S flips the delta negative.

Kev-4B is behind d1 on every check, so it should not become the default scorer.

## Earlier results on the superseded 46-row set

Kept for the record; none of these reproduce against the current labels.

| Scorer | n | ROC-AUC | Precision at 90% recall |
|---|---|---|---|
| Semgrep severity heuristic | 46 | 0.8864 | 0.2000 |
| QLoRA 7B adapter | 45 | 0.5407 | 0.0625 |
| SemIf-shaped Qwen3.5-4B decision scorer | 45 | 0.9070 | 0.2222 |
| LiquidAI d1-3B | 46 | 0.9091 | 0.2500 |

QLoRA failed on both checks, with a mean probability of 0.646 on the two positives against 0.593 on the 43 negatives.
The decision scorer missed the 0.02 AUC margin by 0.0117 and every score was below 0.5.
d1 passed, but 36 of the 46 rows were untouched-file negatives, so that pass was an artifact of the wrong scan scope.
Prediction files for these runs are still under `data/vul4j-eval/`: `vul4j_predictions.jsonl` (QLoRA) and the 45-row decision output is not kept locally.

## What this means for the gate

Both learned scorers clear the configured gate on the expanded set, and d1 clears it with a margin that survives every robustness check tried here.
The gate's own thresholds are still lenient: 14 rows and 5 positives is enough to rank, not enough to publish a precision claim.
Treat d1 as a confirmed lead and keep the heuristic as the fallback until a second real-world set agrees.

## Reproduce

```bash
uv run python scripts/vul4j_scan.py --all-vul4j --all-cwes --changed-only --force --timeout 600
uv run python scripts/vul4j_gate.py \
  --pred d1=data/vul4j-eval/d1_predictions.jsonl \
  --pred kev=data/vul4j-eval/kev_predictions.jsonl
uv run python scripts/vul4j_bootstrap.py \
  --pred d1=data/vul4j-eval/d1_predictions.jsonl \
  --pred kev=data/vul4j-eval/kev_predictions.jsonl
```

Reports: `data/vul4j-eval/gate-report.json` and `data/vul4j-eval/bootstrap.json`.
