"""Rule-prior baselines and within-rule discrimination.

Baselines are out-of-fold logistic regressions on cheap metadata only:
rule name, rule plus file basename, and rule plus CWE/severity/window/line.
Cross-validation groups by entry or by repository.

Within-rule AUC weights each rule that has both classes by positives*negatives,
then bootstraps whole entries for an interval.
"""
import json
import re
import sys

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import OneHotEncoder

import os
from pathlib import Path

ROOT = Path(os.environ.get("TRIAGEMATE_ROOT", str(Path(__file__).resolve().parent.parent)))
AUDIT = Path(os.environ.get("AUDIT_DIR", str(Path(__file__).resolve().parent)))


def read(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def family(cwe):
    m = re.match(r"CWE-(\d+)", cwe or "")
    return m.group(1) if m else ""


def oof(feats, y, groups):
    X = np.array(feats, dtype=object)
    enc = OneHotEncoder(handle_unknown="ignore").fit(X)
    M = enc.transform(X)
    s = np.zeros(len(y))
    for g in sorted(set(groups.tolist())):
        tr, te = groups != g, groups == g
        if len(set(y[tr])) < 2:
            s[te] = float(y[tr].mean())
            continue
        m = LogisticRegression(max_iter=2000).fit(M[tr], y[tr])
        s[te] = m.predict_proba(M[te])[:, 1]
    return s


def weighted_within_rule(y, score, rules):
    num = den = 0.0
    for rule in sorted(set(rules.tolist())):
        m = rules == rule
        p, n = int(y[m].sum()), int((~y[m].astype(bool)).sum())
        if not p or not n:
            continue
        num += roc_auc_score(y[m], score[m]) * p * n
        den += p * n
    return num / den if den else float("nan")


def bootstrap_within(y, score, rules, groups, n=2000, seed=1):
    rng = np.random.default_rng(seed)
    uniq = list(dict.fromkeys(groups.tolist()))
    members = [np.where(groups == g)[0] for g in uniq]
    out = []
    for _ in range(n):
        idx = np.concatenate([members[i] for i in rng.integers(0, len(uniq), len(uniq))])
        v = weighted_within_rule(y[idx], score[idx], rules[idx])
        if not np.isnan(v):
            out.append(v)
    v = np.array(out)
    return {"valid": len(v), "low": round(float(np.percentile(v, 2.5)), 4),
            "high": round(float(np.percentile(v, 97.5)), 4),
            "share_le_0.5": round(float((v <= 0.5).mean()), 4)}


def main():
    rows = read(f"{ROOT}/data/ghsa-eval/labels.jsonl")
    relabel = {r["id"]: r for r in json.loads(
        open(f"{AUDIT}/relabel.json", encoding="utf-8").read())}
    pool = {r["vul_id"]: r for r in read(f"{ROOT}/data/ghsa-eval/pool.jsonl")}
    pred = {}
    for name in ("d1", "kev"):
        by = {r["id"]: float(r["p_tp"]) for r in read(
            f"{ROOT}/data/ghsa-eval/{name}_predictions.jsonl")}
        pred[name] = np.array([by[r["id"]] for r in rows])
    stored = np.array([r["label"] == "TP" for r in rows]).astype(int)
    hunk = np.array([relabel[r["id"]]["hunk_tp"] for r in rows]).astype(int)
    strict = np.array([family(r["cwe"]) in {family(c) for c in r.get("finding_cwes", [])}
                       for r in rows])
    defs = {"L0 location proxy": stored, "L1 hunk only": hunk,
            "L2 stored + CWE": stored & strict, "L3 hunk + CWE": hunk & strict}
    ent = np.array([r["vul_id"] for r in rows])
    repo = np.array([pool[r["vul_id"]]["repo"] for r in rows])
    rules = np.array([r["rule"].split(".")[-1] for r in rows])
    feats = {
        "rule": [[r["rule"]] for r in rows],
        "rule+basename": [[r["rule"], r["path"].split("/")[-1]] for r in rows],
        "rule+cwe+sev+len+line": [[r["rule"], r["cwe"], r["severity"],
                                   len(r["code_window"].splitlines()), r["line"]]
                                  for r in rows],
        "severity": [[r["severity"]] for r in rows],
        "basename": [[r["path"].split("/")[-1]] for r in rows],
    }
    out = {"baselines": {}, "within_rule": {}}
    for dname, y in defs.items():
        y = y.astype(int)
        print(f"\n{dname}: {int(y.sum())} TP")
        out["baselines"][dname] = {}
        for fname, f in feats.items():
            for gname, g in (("entry", ent), ("repo", repo)):
                s = oof(f, y, g)
                a = roc_auc_score(y, s)
                out["baselines"][dname].setdefault(fname, {})[gname] = round(float(a), 4)
                print(f"  {fname:<24} {gname}-grouped AUC {a:.4f}")
        out["within_rule"][dname] = {}
        base = np.array([float(r["p_tp"]) for r in rows])
        for sname, s in (("heuristic", base), ("d1", pred["d1"]), ("kev", pred["kev"])):
            w = weighted_within_rule(y, s, rules)
            b = bootstrap_within(y, s, rules, ent)
            out["within_rule"][dname][sname] = {
                "auc": round(float(w), 4), "entry_bootstrap": b}
            print(f"  within-rule {sname:<10} {w:.4f}  "
                  f"CI [{b['low']:.3f},{b['high']:.3f}]  share<=0.5 {b['share_le_0.5']:.3f}")
    with open(f"{AUDIT}/baselines.json", "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nwrote {AUDIT}/baselines.json")


if __name__ == "__main__":
    sys.exit(main())
