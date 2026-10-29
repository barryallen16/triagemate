"""TriageMate CLI: `triagemate path/to/project`.

Runs Semgrep, extracts a method window per alert, scores it with the triage
model, and prints real bugs first with a reason and a fix.
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from triage.dataset import build_window
from triage.explain import explain
from triage.decision import MODEL as DECISION_MODEL
from triage.decision import REVISION as DECISION_REVISION, DecisionScorer
from triage.prompts import INSTRUCTIONS, SYSTEM

RULES = ["--config", "p/default", "--config", "p/security-audit",
         "--config", "p/owasp-top-ten"]
SEVERITY = {"ERROR": 3, "WARNING": 2, "INFO": 1}


def run_semgrep(target, out):
    cmd = ["semgrep", *RULES, "--json", "--quiet", "--timeout", "30",
           "--max-target-bytes", "2000000", "--metrics", "off", "-o", str(out), target]
    subprocess.run(cmd, check=False)
    return json.loads(Path(out).read_text())


def fallback_window(path, line, pad=12):
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lo, hi = max(0, line - pad - 1), min(len(lines), line + pad)
    imports = "\n".join(x for x in lines if x.strip().startswith(("package ", "import ")))
    body = "\n".join(lines[lo:hi])
    return "\n\n".join(x for x in (imports, body) if x)


def findings_from(scan, root):
    rows = []
    for f in scan.get("results", []):
        path = Path(f["path"])
        if not path.is_absolute():
            path = root / path
        line = f["start"]["line"]
        got = build_window(path.read_text(encoding="utf-8", errors="replace"),
                           line, None, juliet=False)
        window = got[1] if got else fallback_window(path, line)
        meta = f["extra"].get("metadata", {})
        raw = meta.get("cwe") or ["CWE-000"]
        if isinstance(raw, str):
            raw = [raw]
        cwe = raw[0].split(":")[0].strip()
        rows.append({
            "rule": f["check_id"], "cwe": cwe, "file": str(path),
            "line": line, "code_window": window,
            "severity": f["extra"].get("severity", "WARNING"),
            "message": f["extra"].get("message", ""),
        })
    return rows


class ModelScorer:
    def __init__(self, model_name, adapter=""):
        import torch
        from unsloth import FastLanguageModel
        self.torch = torch
        self.model, self.tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_name, max_seq_length=8192, dtype=None, load_in_4bit=True)
        if adapter:
            from peft import PeftModel
            self.model = PeftModel.from_pretrained(self.model, adapter)
        FastLanguageModel.for_inference(self.model)
        self.tok_tp = self.tokenizer(" TP", add_special_tokens=False).input_ids[0]
        self.tok_fp = self.tokenizer(" FP", add_special_tokens=False).input_ids[0]

    def score(self, row):
        user = (f"RULE: {row['rule']}\nCWE: {row['cwe']}\n"
                f"FILE: {Path(row['file']).name}\n"
                f"CODE:\n```java\n{row['code_window'][:18000]}\n```\n\n{INSTRUCTIONS}")
        prefix = self.tokenizer.apply_chat_template(
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
            tokenize=False, add_generation_prompt=True) + "VERDICT:"
        ids = self.tokenizer(prefix, return_tensors="pt").to(self.model.device)
        with self.torch.no_grad():
            logits = self.model(**ids).logits[0, -1]
            p_tp = self.torch.softmax(
                self.torch.stack([logits[self.tok_tp], logits[self.tok_fp]]), 0)[0].item()
            gen = self.model.generate(**ids, max_new_tokens=96, do_sample=False,
                                      pad_token_id=self.tokenizer.eos_token_id)
        text = self.tokenizer.decode(gen[0][ids.input_ids.shape[1]:],
                                     skip_special_tokens=True)
        return p_tp, text


def heuristic_score(row):
    """Fallback ranking with no model: Semgrep severity, then rule confidence."""
    base = SEVERITY.get(row["severity"], 2) / 4
    return min(base, 0.95), ""


def main(argv=None):
    ap = argparse.ArgumentParser(prog="triagemate")
    ap.add_argument("path")
    ap.add_argument("--model", default="unsloth/Qwen2.5-Coder-7B-Instruct-bnb-4bit")
    ap.add_argument("--adapter", default="")
    ap.add_argument("--scorer", choices=["model", "decision", "heuristic"], default="model")
    ap.add_argument("--decision-model", default=DECISION_MODEL)
    ap.add_argument("--decision-revision", default=DECISION_REVISION)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args(argv)
    root = Path(args.path).resolve()
    if not root.exists():
        sys.exit(f"no such path: {root}")

    with tempfile.TemporaryDirectory() as tmp:
        scan = run_semgrep(str(root), Path(tmp) / "findings.json")
    rows = findings_from(scan, root)
    if args.limit:
        rows = rows[:args.limit]
    if args.scorer == "model":
        scorer = ModelScorer(args.model, args.adapter)
    elif args.scorer == "decision":
        scorer = DecisionScorer(args.decision_model, args.decision_revision, args.adapter)
    else:
        scorer = None
    for row in rows:
        if args.scorer == "decision":
            row["p_tp"], row["confidence"] = scorer.score(row)
            prose = explain(row, "TP" if row["p_tp"] >= 0.5 else "FP")
            row["why"] = prose["why"]
            row["fix"] = prose["fix"]
        elif scorer:
            row["p_tp"], text = scorer.score(row)
            row["why"] = next((l[4:].strip() for l in text.splitlines()
                               if l.upper().startswith("WHY:")), "")
            row["fix"] = next((l[4:].strip() for l in text.splitlines()
                               if l.upper().startswith("FIX:")), "")
        else:
            row["p_tp"], _ = heuristic_score(row)
            prose = explain(row, "TP" if row["p_tp"] >= 0.5 else "FP")
            row["why"] = prose["why"]
            row["fix"] = prose["fix"]
    rows.sort(key=lambda r: -r["p_tp"])
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    print(f"{len(rows)} warnings, real bugs first\n")
    for i, r in enumerate(rows, 1):
        verdict = "BUG " if r["p_tp"] >= 0.5 else "noise"
        confidence = f" c={r['confidence']:.2f}" if "confidence" in r else ""
        print(f"{i:3d}. {verdict} p={r['p_tp']:.2f}{confidence}  {r['file']}:{r['line']}  {r['rule']}")
        if r.get("why"):
            print(f"     why: {r['why']}")
        if r.get("fix"):
            print(f"     fix: {r['fix']}")
    if any(r.get("fix") for r in rows):
        print("\nfix text is guidance, not compiled or tested")


if __name__ == "__main__":
    main()
