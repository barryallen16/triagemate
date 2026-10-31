# A7: audit of the second real-world set

Status: complete, 2026-10-31.
Scope: recompute every published second-set number, re-derive labels from the upstream patches, measure the gate under four label rules, add a rule-prior baseline, and test the d1 criteria prompt and a d1 LoRA.

The scripts live in `audit/`.

## Claim table

| Claim in the previous write-up | Recompute | Verdict |
|---|---|---|
| 174 findings from 68 entries, 85 TP and 89 FP | Independent count from `labels.jsonl` | CONFIRMED |
| Heuristic AUC 0.5886, P@90R 0.4885 | Independent rank AUC and whole-tie P@90R | CONFIRMED |
| d1 AUC 0.6941, P@90R 0.4847, delta +0.1055 | Independent recompute | CONFIRMED, exact delta is +0.1054 |
| Kev AUC 0.7521, P@90R 0.6063, delta +0.1635 | Independent recompute | CONFIRMED |
| d1 fails the second-set gate | Gate under stored L0 labels | CONFIRMED for L0 only, REFUTED as a general claim |
| d1 fails by one row because of tie order | Read `precision_at_recall`, recompute accepted counts | REFUTED, the whole tie is accepted, row order cannot change it |
| Kev is the only scorer that passes | Gate under L0 to L3 and criteria variant | REFUTED, d1 passes L1, L2, L3, and L0 with criteria |
| The label is a fix-location proxy | Patch re-derivation | CONFIRMED, and 41 of 85 positives are method-only |
| "Scanned, no finding: 251" | Scan metadata counts | CORRECTED to 264 |
| "1,252 advisories across 498 repositories" | Pool rebuild with filters | CORRECTED to 1,252 after filters across 488 repositories; 1,279 before non-Java and Vul4J exclusions |
| Entry bootstrap intervals in the note | Independent entry bootstrap | CONFIRMED within rounding |
| Rule prior is not a concern | Rule-only logistic regression | REFUTED on stored labels, rule-only AUC 0.767 beats both models; on hunk-only labels the prior falls to 0.461, below the models |
| d1 beats the heuristic by reading code | Swap-window control | NOT SUPPORTED, within-rule AUC does not fall when code windows are replaced |
| A d1 LoRA fixes the within-rule weakness | LoRA pilot on 3,000 synthetic rows, scored on the 174 real rows | REFUTED, AUC 0.5956, within-rule AUC 0.4378 to 0.4867, no gate pass |
| The method-only rule is the main label-noise source | Manual review of 64 of 85 positives | REFUTED, off-CWE TPs are 8 of 32 real, method-only TPs are 27 of 41 real; CWE mismatch is the stronger noise axis |

## 1. Independent recompute

Script: `recompute.py`.
Output: `recompute.json`.

It does not import `triage`, `scripts`, or sklearn.
Rank AUC, the whole-tie precision-at-recall rule, and the bootstrap are reimplemented.

Second set, 174 rows, 68 entries, 85 positives:

| Scorer | AUC | P@90R | dAUC |
|---|---:|---:|---:|
| heuristic | 0.5886 | 0.4885 | - |
| d1 | 0.6941 | 0.4847 | +0.1054 |
| Kev | 0.7521 | 0.6063 | +0.1635 |

Vul4J set, 14 rows, 10 entries, 5 positives:

| Scorer | AUC | P@90R | dAUC |
|---|---:|---:|---:|
| heuristic | 0.5778 | 0.3571 | - |
| d1 | 0.8000 | 0.5556 | +0.2222 |
| Kev | 0.6667 | 0.4545 | +0.0889 |

Every published number reproduces to four decimals.

## 2. Label re-derivation

Script: `relabel.py`.
Output: `relabel.json`.
Patch cache: `patches/`.

Method: fetch the fix patch for each entry, parse old-side changed lines, expand by the scanner's two lines, and check whether the finding line falls in a changed hunk.

Result:

- 174 rows, 68 entries, 0 fetch failures.
- 85 stored TP.
- 44 TP sit on a changed hunk line.
- 41 TP sit only inside a method that contains a changed line.
- 0 stored FP sits on a changed hunk line.
- 0 rows have a file absent from the patch.

The scanner's fallback rule is intentional.
The problem is that 48 percent of the positives rely on it.
A finding in a large method that the fix touches somewhere else is a weak positive.
The adjudication in section 9 refines this: CWE mismatch is the stronger noise axis, with 8 of 32 off-CWE TPs real against 27 of 41 method-only TPs.

The first parser version counted GitHub's three context lines as changed and over-counted hunk hits.
The fixed parser tracks old-side line numbers through the patch body.
Zero FP hunk hits is the sanity check.

## 3. Label sensitivity

Script: `sensitivity.py`.
Output: `sensitivity.json`.

Definitions:

- L0: stored labels, hunk or touched method, any CWE. 85 TP.
- L1: hunk-only, any CWE. 44 TP.
- L2: stored labels restricted to findings whose rule CWE matches the advisory CWE. 53 TP.
- L3: hunk-only and CWE-consistent. 28 TP.

| Definition | TP | Heuristic AUC / P@90R | d1 AUC / P@90R | d1 gate | Kev AUC / P@90R | Kev gate |
|---|---:|---|---|---|---|---|
| L0 | 85 | 0.5886 / 0.4885 | 0.6941 / 0.4847 | FAIL | 0.7521 / 0.6063 | PASS |
| L1 | 44 | 0.5220 / 0.2529 | 0.6672 / 0.2778 | PASS | 0.6612 / 0.3226 | PASS |
| L2 | 53 | 0.6223 / 0.3046 | 0.7861 / 0.5000 | PASS | 0.7594 / 0.4364 | PASS |
| L3 | 28 | 0.5235 / 0.1609 | 0.8372 / 0.3514 | PASS | 0.7167 / 0.2241 | PASS |

Entry-bootstrap 95 percent interval for dAUC:

- L0: d1 `[-0.095, +0.323]`, Kev `[-0.037, +0.341]`.
- L1: d1 `[-0.070, +0.435]`, Kev `[-0.019, +0.336]`.
- L2: d1 `[-0.051, +0.343]`, Kev `[-0.050, +0.300]`.
- L3: d1 `[+0.089, +0.544]`, Kev `[-0.000, +0.430]`.

The previous "d1 fails" conclusion is not robust.
It holds only on L0.
Only d1 under L3 has an interval strictly above zero, and L3 has only 28 positives.
The right report is a label-sensitivity table, not a single verdict.

## 4. d1 criteria prompt

Script: `d1_criteria_kaggle.py`.
Predictions: `audit/d1_criteria_predictions.jsonl`.
Score: `audit/score-d1_criteria.json`.

The only change from the previous d1 scorer is the cookbook's optional `criteria` field:

- true: the unsafe pattern is present and untrusted input can reach it without an effective guard.
- false: the pattern is absent or neutralized, the code is unreachable from untrusted input, or the alert is style-only.

| Definition | TP | d1 criteria AUC / P@90R | dAUC | Gate |
|---|---:|---|---:|---|
| L0 | 85 | 0.7028 / 0.5132 | +0.1141 | PASS |
| L1 | 44 | 0.6461 / 0.3053 | +0.1240 | PASS |
| L2 | 53 | 0.7758 / 0.4898 | +0.1534 | PASS |
| L3 | 28 | 0.8105 / 0.3562 | +0.2871 | PASS |

Entry-bootstrap dAUC intervals: L0 `[-0.083, +0.325]`, L1 `[-0.071, +0.390]`, L2 `[-0.062, +0.334]`, L3 `[+0.053, +0.535]`.

The criteria prompt fixes the stored-label gate failure: P@90R 0.5132 against the heuristic's 0.4885.
Weighted within-rule AUC is 0.4739, still below 0.5.
The gain is rule-level calibration, not better code reading.

## 5. Rule-prior baseline

Script: `baselines.py`.
Output: `baselines.json`.

Out-of-fold logistic regressions on metadata only, grouped by entry or by repository.
Feature sets: rule, rule plus file basename, and rule plus CWE, severity, window length and line.
Severity alone and basename alone are reported as sanity checks.

| Definition | TP | rule entry | rule repo | rule+basename entry | rule+basename repo |
|---|---:|---:|---:|---:|---:|
| L0 stored | 85 | 0.7666 | 0.7873 | 0.7862 | 0.7988 |
| L1 hunk only | 44 | 0.4612 | 0.5867 | 0.4906 | 0.6084 |
| L2 stored + CWE | 53 | 0.7684 | 0.8194 | 0.7804 | 0.8367 |
| L3 hunk + CWE | 28 | 0.6743 | 0.6469 | 0.7178 | 0.6802 |

The third feature set, rule plus CWE, severity, window length and line, reaches 0.7307 at L0, 0.5705 at L1, 0.8860 at L2 and 0.8434 at L3, entry-grouped.
The L2 and L3 numbers are inflated by construction: both labels require the finding CWE to match the advisory CWE, and that feature set contains the finding CWE.
They are not evidence that vulnerability location is predictable from metadata.

Severity alone is below chance everywhere: 0.3950 at L0, 0.1571 at L1, 0.3775 at L2, 0.0915 at L3, entry-grouped.
Basename alone is 0.2181, 0.1565, 0.1698 and 0.2423.

The stored-label ranking is reproducible from rule priors alone:

- rule only 0.7666 entry-grouped, 0.7873 repo-grouped.
- rule plus basename 0.7862 and 0.7988.
- d1 0.6941, d1 with criteria 0.7028, Kev 0.7521.

Under the hunk-only label the rule prior collapses:

- rule only 0.4612 entry-grouped, 0.5867 repo-grouped.
- rule plus basename 0.4906 and 0.6084.
- d1 0.6672, d1 with criteria 0.6461, Kev 0.6612.

So the metadata baseline beats the models only on the loose label.
That label, not code reading, is what a rule lookup explains.
Under the strict label the ordering flips, though the entry-grouped baseline is below chance, which means the rule prior actively misleads on unseen entries with this label.

Weighted within-rule AUC, weighting each mixed rule by positives times negatives, with an entry bootstrap:

| Definition | heuristic | d1 | d1 criteria | Kev |
|---|---|---|---|---|
| L0 | 0.500 [0.500, 0.500] | 0.4297 [0.225, 0.670] | 0.4739 [0.230, 0.748] | 0.6757 [0.501, 0.865] |
| L1 | 0.500 [0.500, 0.500] | 0.5462 [0.414, 0.731] | 0.5008 [0.384, 0.695] | 0.5244 [0.354, 0.739] |
| L2 | 0.500 [0.500, 0.500] | 0.4571 [0.222, 0.666] | 0.5190 [0.273, 0.746] | 0.7500 [0.557, 0.902] |
| L3 | 0.500 [0.500, 0.500] | 0.5495 [0.389, 0.733] | 0.5012 [0.351, 0.743] | 0.6449 [0.441, 0.845] |

No d1 variant has a within-rule interval strictly above 0.5.
Kev does on L0 and L2, so it finds some within-rule signal on the stored label, but its overall AUC still trails the rule prior.

## 6. Documentation corrections

Confirmed errors:

1. `notes/a6-second-real-world-set.md` line 58: 251 should be 264.
2. `notes/a6-second-real-world-set.md` line 15 and `README.md` line 55: 498 should be 488, and 1,252 is after the non-Java and Vul4J filters, not before them.
3. `notes/a6-second-real-world-set.md` lines 121 to 123 and `README.md` line 63: the tie-order claim is false.
   The whole threshold tie is accepted, so row order cannot change the result.
   At severity 0.5 the heuristic accepts all 174 rows, recall 1.0, precision 85/174 = 0.4885.
   d1's cut accepts 163 rows with 79 TP, precision 79/163 = 0.4847.
4. The "d1 fails, Kev is the only pass" conclusion is replaced by the L0 to L3 table and the criteria result.
5. The note now says 41 of 85 positives are method-only.

Committed:

- `f3cf712` correct second set counts and tie claim
- `4311be5` correct second set card claims
- `24f4a66` add d1 criteria result to second set
- `09df24d` add second set audit note

The updated card was uploaded to Hugging Face in dataset commit `346dcfb891bd1609b43cc553d811c7d6d1eea9bb`.
The raw README hash matches the local `docs/hf-dataset-card.md` (`fcadee8f...`), and the raw labels still hash to `b3232a60...`.

`progress.md` is updated in place and is not in git.

## 7. LoRA

Script: `d1_lora_kaggle.py`.
Kaggle run: `run_20261031_112516_a0111e`.
Status: complete, training loss 0.438 to 0.036, train runtime 2,795 seconds.
Training: 3,000 balanced rows from the 7,797-row synthetic train split, 1 epoch, max sequence 1536, LoRA r=16 alpha=32, language-model modules only, lr 2e-4.
Evaluation: the merged model on the 174 real rows with the same criteria prompt as section 4.
Predictions: `audit/d1_lora_predictions.jsonl`.
Score: `audit/score-d1_lora.json`.

| Definition | TP | LoRA AUC / P@90R | dAUC vs heuristic | Gate |
|---|---:|---|---:|---|
| L0 | 85 | 0.5956 / 0.5000 | +0.0070 | FAIL |
| L1 | 44 | 0.5214 / 0.2500 | -0.0006 | FAIL |
| L2 | 53 | 0.5083 / 0.3077 | -0.1140 | FAIL |
| L3 | 28 | 0.5382 / 0.1605 | +0.0147 | FAIL |

Weighted within-rule AUC: 0.4592 at L0, 0.4378 at L1, 0.4607 at L2, 0.4867 at L3.
Every entry-bootstrap interval includes 0.5, and 54 to 76 percent of resamples sit at or below 0.5.
The LoRA lands at the heuristic on the stored label and below zero-shot d1 on every other definition.
Its scores correlate 0.158 with the zero-shot criteria scores, and the distribution is bimodal rather than calibrated.
Training loss fell cleanly, so this is transfer failure, not a broken run.

The promotion gate is a within-rule AUC interval above 0.5 and a win over the rule-prior baseline.
Neither holds, so the negative result is recorded and the full 7,797-row run is not launched.

## 8. Swap-window control

Script: `d1_swap_kaggle.py`.
Kaggle run: `run_20261031_113851_be630b`.
Status at the last update: complete.
Script: `score_swap.py`, output `score-swap.json`.
Predictions: `d1_swap_predictions.jsonl`, plan `swap_plan.json`.

Every row keeps its rule, CWE, severity, file, line and message.
Only the code window is replaced:

- global: the window comes from a random other row, derangement seeded at 3407.
- rule: the window comes from another row with the same rule.
  Six singleton rules keep their own window and are listed in `swap_plan.json`.

348 rows total, same model, prompt and criteria as the criteria run.

Result on the stored labels, 85 TP:

| Variant | AUC | P@90R | within-rule AUC | identity minus this AUC, entry CI |
|---|---:|---:|---:|---|
| identity | 0.7028 | 0.5132 | 0.4739 | - |
| global swap | 0.6348 | 0.5066 | 0.5896 | -0.059 to +0.185 |
| rule swap | 0.6739 | 0.5232 | 0.4444 | -0.034 to +0.102 |

The other definitions follow the same pattern:

| Definition | identity AUC | global AUC | rule AUC |
|---|---:|---:|---:|
| L0 | 0.7028 | 0.6348 | 0.6739 |
| L1 | 0.6461 | 0.6005 | 0.6019 |
| L2 | 0.7758 | 0.7521 | 0.7215 |
| L3 | 0.8105 | 0.7387 | 0.7440 |

Replacing the code does not lower within-rule AUC.
It rises from 0.4739 to 0.5896 under the global swap and falls to 0.4444 under the rule swap.
A model that ranked by code would lose its within-rule signal when the code is replaced.
This one does not, and every AUC difference interval includes zero.

The control gives no evidence that d1 uses the code to separate true from false alerts.
It is consistent with rule-level calibration plus noise.
The earlier hint that d1 is anti-correlated within rule on the original windows survives the swap, so that weakness is not a code-reading strength either.

## 9. Manual adjudication

Script: `write_adjudication.py`.
Packet: `adjudication_packet.md`.
Rows and verdicts: `adjudication.json`.
Sample: `adjudication_sample.json`.

The sample is a census of the two weak groups plus 15 random CWE-matched TPs:

- all 32 off-CWE TPs
- all 41 method-only TPs
- 15 random on-CWE TPs, seed 3407
- 64 unique rows after the overlaps, 75 percent of the 85 stored positives

Verdicts:

- `real`: the flagged sink is the vulnerability the fix patch addresses.
- `partial`: same method or sink, but the patch fixes a different weakness or disables the endpoint without fixing the sink.
- `not-real`: the patch does not touch the flagged construct, or the finding is unrelated to the advisory.

| Group | Rows | Real | Partial | Not real | Real rate |
|---|---:|---:|---:|---:|---:|
| off-CWE (census) | 32 | 8 | 5 | 19 | 25.0% |
| method-only (census) | 41 | 27 | 2 | 12 | 65.9% |
| on-CWE (random 15 of 53) | 15 | 15 | 0 | 0 | 100% |
| all sampled | 64 | 39 | 5 | 20 | 60.9% |

The groups overlap, so the rows do not add to 64.

The main result is that CWE mismatch is a better noise signal than the hunk/method split.
Only 8 of 32 off-CWE TPs are real, against 27 of 41 method-only TPs and 15 of 15 sampled on-CWE TPs.
The earlier guess that method-only rows were the main problem was wrong.

Most off-CWE noise is a different weakness in the same file or method:

- MCMS MD5 finding against a SQL-injection fix
- ff4j CRLF log finding against an RCE type check
- IzPack deserialization findings against a path-traversal fix
- JPA DefaultHttpClient finding against an XSS policy
- Karaf plaintext-socket finding against deserialization hardening
- HTML Publisher SHA1 finding against XSS escaping
- nine CometVisu path-traversal rows against an SSRF/XSS fix

Five rows are partial because the patch contains the weakness without fixing it:

- two HtmlUnit transformer findings get FEATURE_SECURE_PROCESSING but external access stays enabled
- the XXL-JOB request mapping is still unrestricted after the executorAddress SSRF fix
- two CometVisu saveConfig findings become unreachable when the endpoint is removed

Eight off-CWE rows are still real because the advisory CWE does not describe the sink the patch fixes.
Examples: Solr (XXE resolver fix), Dropwizard (EL escaping), Conductor (script-engine sandbox), AWS region metadata (XXE fix), XMP (XSLT access restrictions), Liferay (XSLT secure processing) and OpenAM (deserialization filter).

Caveats:

- The off-CWE and method-only rates are exact for those groups because both are censuses.
- The on-CWE rate is a 15-row random sample of 53, so 15 of 15 does not prove all 53 are real.
- The 21 unsampled on-CWE TPs were not reviewed.
- One reviewer assigned every verdict, with a one-line reason per row in `adjudication.json`.

What this means for the gate:

- The L2 and L3 labels are cleaner by construction, but part of their gain over L0 is label cleaning, not model skill.
- The adjudication supports reporting L1, L2 and L3 beside L0 instead of treating L0 as ground truth.
- It also argues against training on the loose real labels: most off-CWE positives are not the reported vulnerability.

## 10. Open items

- Optional: add the adjudication result to the Hugging Face dataset card if the label-proxy caveat needs a number.

## 11. Reproduce

```bash
cd audit
uv run --with numpy --with scikit-learn python recompute.py
python3 relabel.py
uv run --with numpy python sensitivity.py
uv run --with numpy python score_pred.py d1_criteria=./d1_criteria_predictions.jsonl
uv run --with numpy python score_pred.py d1_lora=./d1_lora_predictions.jsonl
uv run --with numpy python score_swap.py
uv run --with numpy --with scikit-learn python baselines.py
python3 build_adjudication.py
python3 write_adjudication.py
```

The relabel script reads the cached patches, so it does not need network access after the first run.
