# A6: second real-world set from GitHub advisories

## Why

The d1 result rested on 14 alerts from 10 Vul4J entries.
Fourteen rows can rank scorers but cannot show that a gain generalizes.
This set comes from a different source, a different repository mix and a different CWE mix, and it uses the same scan and label code.

## Source and selection

The source is the OSV bulk export for Maven, which is the GitHub advisory database plus other feeds.
It held 7,218 Maven advisories on 2026-10-30.

Selection keeps an advisory only when it has a target CWE and a full 40-character GitHub commit link.
That leaves 1,279 advisories before the non-Java and Vul4J exclusions and 1,252 after them, across 488 repositories.
The sample is 400 entries across 12 CWE families, at most two entries per repository, from 314 repositories.
Repositories that ship JavaScript under Maven coordinates (jQuery, Bootstrap and similar) are dropped, and so are commits that Vul4J already uses.

Script: `scripts/ghsa_pool.py`.
Pool: `data/ghsa-eval/pool.jsonl`.

Selected CWE mix:

| CWE | Entries |
|---|---|
| CWE-611 | 54 |
| CWE-22 | 54 |
| CWE-502 | 54 |
| CWE-79 | 54 |
| CWE-94 | 43 |
| CWE-918 | 35 |
| CWE-89 | 28 |
| CWE-601 | 23 |
| CWE-74 | 23 |
| CWE-78 | 21 |
| CWE-77 | 7 |
| CWE-1336 | 4 |

## Scan

Script: `scripts/ghsa_scan.py`.
It imports the Vul4J scanner, so checkout, diff hunks, Semgrep invocation, test-source exclusion, code windows and heuristic scores are the same code.

One difference is the checkout.
A full depth-2 fetch of a monorepo costs hundreds of MB, so the scanner fetches trees with `--filter=blob:none` and materializes only the Java files the fix touches.
GeoTools went from a 642 MB and 10-minute checkout to 4 KB and 46 seconds.
Files that the fix adds have no old-side content and are skipped.

Scan settings match Vul4J's changed-file runs: `p/security-audit` and `p/owasp-top-ten`, changed Java files only, 25 Java files per entry at most.
Test sources are excluded, and this set also drops rows under test modules that are not in `src/test`, such as `hugegraph-test`.
That extra filter removed 2 rows, both false positives.

Result over 400 sampled entries:

| Outcome | Entries |
|---|---|
| Scanned, at least one finding | 69 |
| Scanned, no finding | 264 |
| No changed Java file | 58 |
| Patch wider than 25 Java files | 8 |
| Fix commit not reachable | 1 |

After the test-module filter the set is 68 entries and 174 findings, 85 location-proxy true positives and 89 false positives.
The whole scan took about two hours on this 2 CPU VPS.

Data: `data/ghsa-eval/labels.jsonl`.

## Label set

The rule is unchanged.
A finding is a true positive when its line overlaps a line the fix changes, within two lines of context, or falls inside a method the fix changes.
Every row sits in a file the fix touches, and rule CWE metadata does not decide the label.

Of the 85 positives, 44 sit on a changed hunk line and 41 sit only inside a method that contains a changed line.
The second group is 48 percent of the positives and is a much weaker label than "the fix changed this line".

Positives by advisory CWE:

| CWE | TP |
|---|---|
| CWE-611 | 37 |
| CWE-918 | 14 |
| CWE-502 | 10 |
| CWE-94 | 7 |
| CWE-22 | 6 |
| CWE-601 | 3 |
| CWE-89 | 2 |
| CWE-78 | 2 |
| CWE-79 | 2 |
| CWE-74 | 1 |
| CWE-77 | 1 |

Three entries were checked against their upstream patches:

| Entry | What the patch does |
|---|---|
| GHSA-rr59-h6rh-v84v | Apache Zeppelin replaces two direct `DocumentBuilderFactory.newInstance()` calls at the flagged lines with a hardened factory |
| GHSA-3xrr-7m6p-p7xh | HtmlUnit adds `FEATURE_SECURE_PROCESSING` to the transformer factory that the alert points at |
| GHSA-v7gr-mqpj-wwh3 | openHAB rewrites the CometVisu servlet path handling across the flagged methods; the advisory is SSRF/XSS, so the path-traversal alerts are the weakest fits in the set |

The first two are genuine security fixes at the flagged line.
The openHAB entry is a broad refactor, and its 16 rows include 11 path-traversal alerts that the advisory does not name.
It stays in the set under the mechanical rule, and the checks below show the result without it too.

This is a location proxy, not proof that each positive is the exact CVE.

## Gate result

The gate compares each scorer against the Semgrep severity heuristic.
It needs at least eight entries, ROC-AUC at least 0.02 above the heuristic, and no loss in precision at 90% recall.

| Scorer | n | Entries | ROC-AUC | Precision at 90% recall | Delta AUC |
|---|---|---|---|---|---|
| Severity heuristic | 174 | 68 | 0.5886 | 0.4885 | - |
| LiquidAI d1-3B | 174 | 68 | 0.6941 | 0.4847 | +0.1054 |
| LiquidAI d1-3B + criteria | 174 | 68 | 0.7028 | 0.5132 | +0.1141 |
| Kev-4B | 174 | 68 | 0.7521 | 0.6063 | +0.1635 |

d1 clears the AUC margin, but precision at 90% recall is 0.0038 lower on the stored labels, so the gate fails there.
Kev-4B passes both checks, with +0.1635 AUC and +0.1178 precision.
d1 without criteria is not promoted on this set.

Adding the cookbook's true/false `criteria` to the d1 prompt fixes that gate failure.
P@90R rises to 0.5132, above the heuristic's 0.4885, and AUC rises to 0.7028.
It passes under all four label definitions below.
The gain is rule-level calibration: weighted within-rule AUC is 0.4739, still below 0.5.

On the stored labels a metadata lookup matches or beats both models.
Out-of-fold logistic regression on rule name alone reaches 0.767 AUC, and rule plus file name reaches 0.786 entry-grouped and 0.799 repo-grouped, against d1's 0.694 and Kev's 0.752.
Under the hunk-only label the same baseline falls to 0.461 entry-grouped and 0.587 repo-grouped, below d1's 0.667, so the loose label is what metadata explains.
A swap-window control finds no code-reading advantage either: replacing each row's code window with another row's moves within-rule AUC from 0.474 to 0.590 after a global swap and 0.444 after a within-rule swap, and every AUC difference interval includes zero.

The precision check is brittle here, but not because of tie order.
The heuristic has only two scores: 105 rows at 0.75 and 69 at 0.5.
Reaching 90% recall needs 77 positives, and only 59 of them sit at 0.75, so the cut moves to 0.5.
At that threshold every remaining row is accepted, recall is 1.0, and precision is 85/174 = 0.4885, which is the heuristic's overall precision.
`precision_at_recall` accepts the whole threshold tie, so row order cannot change the result.
d1's own cut accepts 163 rows with 79 positives, recall 0.929 and precision 79/163 = 0.4847, so it misses by 0.0038.
The reason is the cut, not row order.

## Robustness

`scripts/vul4j_bootstrap.py` on the same rows:

| Resample | 95% interval for the AUC delta | P(delta <= 0) |
|---|---|---|
| Rows, d1 | -0.0080 to +0.2215 | 0.0365 |
| Entries, d1 | -0.0952 to +0.3232 | 0.1855 |
| Rows, Kev | +0.0673 to +0.2581 | 0.0010 |
| Entries, Kev | -0.0375 to +0.3409 | 0.0560 |

Leave-one-entry-out never drops the d1 delta below +0.0185, and that minimum comes from dropping the 18-row GeoTools entry, which has no positives.
For Kev the minimum is +0.0644, also from GeoTools.
Without the openHAB entry both deltas stay positive: d1 at +0.1900 and Kev at +0.1670.
The entry bootstrap is the check that matters, and neither scorer excludes zero at entry level.

d1 loses to the heuristic inside four entries:

| Entry | Rows | Positives | Delta AUC |
|---|---|---|---|
| GHSA-f729-58x4-gqgf | 11 | 4 | -0.5000 |
| GHSA-65hj-9ppw-77xc | 2 | 1 | -0.5000 |
| GHSA-83w4-x5w9-hf4h | 7 | 1 | -0.0833 |
| GHSA-v7gr-mqpj-wwh3 | 16 | 11 | -0.0455 |

Kev loses inside five entries, each with one or two positives, each costing -0.5 AUC.

## The two sets together

| Set | Rows | Entries | Scorer | AUC delta | Gate |
|---|---|---|---|---|---|
| Vul4J | 14 | 10 | d1 | +0.2222 | pass |
| Vul4J | 14 | 10 | Kev | +0.0889 | pass |
| GitHub advisories | 174 | 68 | d1 | +0.1055 | fail on precision (L0) |
| GitHub advisories | 174 | 68 | d1 + criteria | +0.1141 | pass (L0) |
| GitHub advisories | 174 | 68 | Kev | +0.1635 | pass |

d1 has the bigger Vul4J result and the smaller second-set result, and it fails the second-set gate on the stored labels.
The verdict is label-dependent: under a hunk-only rule, a CWE-consistent rule, or both, d1 passes (AUC 0.667 to 0.837).
Kev passes all four definitions, but its Vul4J row bootstrap puts P(delta <= 0) at 0.3502 and the entry bootstrap at 0.3885, so its Vul4J pass is not supported.
Neither scorer is promoted.

The gate rule as written asks for a pass on both sets.
Kev meets that, and d1 does not on the stored labels.
Promotion is still declined because Kev has no `triage/` scorer, only a Kaggle evaluation payload, and because the intervals that matter include zero on one set each.

## What this means

The d1 Vul4J pass did not replicate under the gate's own rule on the stored labels.
On 174 rows from 68 entries d1 ranks better than severity, by +0.1054 AUC, but the gain is not significant once entries are resampled, and the precision check is a near-tie against a two-valued baseline.
That verdict is not robust to the label rule: hunk-only, CWE-consistent, and hunk plus CWE definitions all make d1 pass.
The honest reading is that the stored location proxy is too generous in one direction and too noisy in another, and the result is label-dependent rather than a clean failure.

Kev-4B is the better bet on the larger set, and the only scorer that passes both gates, but its Vul4J intervals are wide enough to include zero.

Two things follow:

- The heuristic stays the default scorer.
- The gate needs both sets.
  Vul4J is the benchmark of record, and this set is the larger and more diverse check.
  A promotion should require a pass on both, not on either, plus a scorer that ships in `triage/`.

The precision check should not use a two-valued baseline cut without tie handling.
That is a change to `scripts/vul4j_gate.py` and is not made here.

## Reproduce

```bash
cd /home/ubuntu/all-vul-plus-work/all-vul/triagemate-realworld-vul4j
uv run python scripts/ghsa_pool.py --limit 400
uv run python scripts/ghsa_scan.py --timeout 600
uv run python scripts/vul4j_gate.py \
  --labels data/ghsa-eval/labels.jsonl \
  --pred d1=data/ghsa-eval/d1_predictions.jsonl \
  --pred kev=data/ghsa-eval/kev_predictions.jsonl
uv run python scripts/vul4j_bootstrap.py \
  --labels data/ghsa-eval/labels.jsonl \
  --pred d1=data/ghsa-eval/d1_predictions.jsonl \
  --pred kev=data/ghsa-eval/kev_predictions.jsonl
```
