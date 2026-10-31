"""d1-3B evaluation combining Targeted Sink annotation with Proven Criteria.

Evaluates:
1. GHSA Identity with Targeted Sink + Criteria (174 rows)
2. GHSA Rule Swap Control with Targeted Sink + Criteria (174 rows)
3. Vul4J Identity with Targeted Sink + Criteria (14 rows)

Usage on Kaggle: python d1_targeted_criteria_v2_kaggle.py
"""
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

MODEL = "LiquidAI/d1-3B"
GHSA_URL = os.environ.get(
    "TRIGEMATE_DATA_URL",
    "https://huggingface.co/datasets/barryallen16/triagemate/"
    "resolve/main/ghsa-scan-labeled.jsonl")
VUL4J_URL = os.environ.get(
    "TRIGEMATE_VUL4J_URL",
    "https://huggingface.co/datasets/barryallen16/triagemate/"
    "resolve/main/vul4j-scan-labeled.jsonl")

WORK = Path(os.environ.get("TRIGEMATE_WORK", "/content" if Path("/content").exists() else "/kaggle/working"))
if not WORK.exists():
    WORK = Path("/tmp")

OUT_GHSA_IDENTITY = WORK / "d1_targeted_criteria_identity_ghsa.jsonl"
OUT_GHSA_SWAP = WORK / "d1_targeted_criteria_swap_ghsa.jsonl"
OUT_VUL4J_IDENTITY = WORK / "d1_targeted_criteria_identity_vul4j.jsonl"

MAX_CHARS = 10000
BATCH = 1
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

RULE_PATTERNS = {
    'documentbuilderfactory': [r'DocumentBuilderFactory', r'DocumentBuilder', r'getDocBuilder', r'parserFactory', r'builderFactory'],
    'transformerfactory': [r'TransformerFactory', r'Transformer', r'newTransformer'],
    'saxparserfactory': [r'SAXParserFactory', r'newSAXParser', r'SAXParser'],
    'path-traversal': [r'new\s+File\b', r'Paths\.get\b', r'getResource\b', r'FileInputStream\b', r'openStream\b', r'getRequestedFile\b', r'File\b'],
    'formatted-sql-string': [r'String\.format\b', r'createQuery\b', r'prepareStatement\b', r'SELECT\b', r'execute\b', r'\+'],
    'object-deserialization': [r'new\s+ObjectInputStream\b', r'\.readObject\b', r'ObjectInputStream\b', r'readUnshared\b', r'resolveClass\b'],
    'unrestricted-request-mapping': [r'@RequestMapping\b', r'@GetMapping\b', r'@PostMapping\b'],
    'unencrypted-socket': [r'new\s+ServerSocket\b', r'new\s+Socket\b', r'ServerSocket\b'],
    'cookie-missing-httponly': [r'setHttpOnly\b', r'new\s+Cookie\b', r'Cookie\b'],
    'cookie-missing-secure-flag': [r'setSecure\b', r'new\s+Cookie\b', r'Cookie\b'],
    'script-engine-injection': [r'\.eval\(', r'ScriptEngine\b'],
    'use-of-md5': [r'MessageDigest\.getInstance', r'MD5', r'md5\b'],
    'use-of-sha1': [r'MessageDigest\.getInstance', r'SHA-1', r'sha1\b'],
    'url-rewriting': [r'encodeURL\b', r'encodeRedirectURL\b', r'response\.encodeURL\b', r'FormAuthenticator\b', r'getSession\b'],
    'el-injection': [r'ExpressionFactory\b', r'createValueExpression\b', r'evaluate\b', r'buildConstraintViolationWithTemplate\b', r'interpolate\b'],
    'spel-injection': [r'parseExpression\b', r'SpelExpressionParser\b', r'PARSER\b'],
    'crlf-injection-logs': [r'log\.(info|debug|warn|error)\b', r'logger\.(info|debug|warn|error)\b'],
    'tainted-session-from-http-request': [r'session\.setAttribute\b', r'setAttribute\b'],
    'request-host-used': [r'getHeader\(\"Host\"\)', r'getServerName\b'],
    'bad-hexa-conversion': [r'toHexString\b', r'Integer\.toHexString\b', r'0x'],
}

def find_sink_index(window, rule):
    lines = window.splitlines()
    rule_lower = rule.lower()
    matched_idx = []
    
    for key, patterns in RULE_PATTERNS.items():
        if key in rule_lower:
            for pat in patterns:
                for idx, line in enumerate(lines):
                    trimmed = line.strip()
                    if not trimmed.startswith(('import ', 'package ', '//', '/*', '*')):
                        if re.search(pat, line, re.IGNORECASE):
                            matched_idx.append(idx)
                if matched_idx:
                    break
            break
            
    if not matched_idx:
        tokens = [t for t in rule.split('.')[-1].replace('-', '_').split('_') if len(t) > 3]
        for idx, line in enumerate(lines):
            trimmed = line.strip()
            if not trimmed.startswith(('import ', 'package ', '//', '/*', '*')):
                if any(t in line.lower() for t in tokens):
                    matched_idx.append(idx)
                    
    if not matched_idx:
        return len(lines) // 2
    return matched_idx[0]


QUESTION = (
    "Is this static-analysis warning a real, exploitable security bug in the code below? "
    "Focus on the flagged alert line (marked with >>>). Answer yes only if the vulnerable "
    "pattern is present and reachable in this code."
)
CRITERIA = {
    "true": (
        "The code contains the unsafe pattern named by the rule at the flagged alert line, "
        "and untrusted input can reach it without an effective guard."
    ),
    "false": (
        "The pattern is absent or neutralized, or the code is unreachable from untrusted input, "
        "or the alert is style-only."
    ),
}
QUESTIONS = {"tp": {"type": "noul", "instructions": QUESTION, "criteria": CRITERIA}}


def state_of_annotated(row, window_override=None):
    raw_window = (window_override if window_override is not None else row.get("code_window", ""))[:MAX_CHARS]
    lines = raw_window.splitlines()
    sink_idx = find_sink_index(raw_window, row["rule"])
    flagged_line_text = lines[sink_idx].strip() if 0 <= sink_idx < len(lines) else ""
    
    annotated = []
    for idx, l in enumerate(lines):
        if idx == sink_idx:
            annotated.append(f">>> [ALERT LINE {row.get('line', 0)}]: {l}")
        else:
            annotated.append(f"    {l}")
    window = "\n".join(annotated)

    header = [
        f"Rule: {row['rule']}",
        f"CWE: {row['cwe']}",
        f"Severity: {row.get('severity', 'WARNING')}",
        f"File: {str(row['file']).split('/')[-1]}",
        f"Flagged Line: {row.get('line', 0)}",
        f"Flagged Sink Statement: {flagged_line_text}",
    ]
    if row.get("message"):
        header.append(f"Rule message: {row['message']}")
    return "\n".join(header) + f"\n\nJava (Flagged alert line marked with >>>):\n```java\n{window}\n```"


def build_rule_swap(rows, seed=3407):
    """Swap code windows within the same rule (derangement where possible)."""
    rng = random.Random(seed)
    by_rule = {}
    for i, r in enumerate(rows):
        by_rule.setdefault(r["rule"], []).append(i)
    
    swapped_windows = [None] * len(rows)
    for rule, indices in by_rule.items():
        if len(indices) == 1:
            swapped_windows[indices[0]] = rows[indices[0]]["code_window"]
        else:
            shuffled = list(indices)
            for _ in range(100):
                rng.shuffle(shuffled)
                if all(a != b for a, b in zip(indices, shuffled)):
                    break
            for orig_idx, new_idx in zip(indices, shuffled):
                swapped_windows[orig_idx] = rows[new_idx]["code_window"]
    return swapped_windows


def score_dataset(model, rows, out_path, window_overrides=None):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    with out_path.open("w", encoding="utf-8") as fh:
        for start in range(0, len(rows), BATCH):
            chunk = rows[start:start + BATCH]
            t0 = time.time()
            states = []
            for i, row in enumerate(chunk):
                w_override = window_overrides[start + i] if window_overrides else None
                states.append(state_of_annotated(row, w_override))
            with torch.inference_mode():
                answers = model.system_one_batch([(s, QUESTIONS) for s in states])
            elapsed = time.time() - t0
            for row, answer in zip(chunk, answers):
                p_tp = float(answer["answers"]["tp"]["noul"])
                fh.write(json.dumps({
                    "id": row["id"],
                    "label": row["label"],
                    "p_tp": p_tp,
                    "confidence": round(max(p_tp, 1.0 - p_tp), 6),
                    "seconds": round(elapsed / len(chunk), 3),
                }) + "\n")
            fh.flush()
            done = min(start + BATCH, len(rows))
            if done % 20 == 0 or done == len(rows):
                print(f"  {done}/{len(rows)}  {time.time() - started:.0f}s", flush=True)
    print(f"predictions written to {out_path}", flush=True)


def fetch_or_fallback(url, local_fallback):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        data = urllib.request.urlopen(req, timeout=30).read().decode("utf-8")
        rows = [json.loads(line) for line in data.splitlines() if line.strip()]
        if rows:
            return rows
    except Exception as e:
        print(f"Fetch failed ({e}), checking fallback...", flush=True)
    
    fb = Path(local_fallback)
    if fb.exists():
        return [json.loads(line) for line in fb.read_text(encoding="utf-8").splitlines() if line.strip()]
    return []


def main():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "transformers>=5.14", "accelerate"])
    global torch
    import torch
    from transformers import AutoModel

    print("Fetching GHSA dataset...", flush=True)
    ghsa_rows = fetch_or_fallback(GHSA_URL, "data/ghsa-eval/labels.jsonl")
    if not ghsa_rows:
        sys.exit("Error: Could not load GHSA dataset")
    print(f"Loaded {len(ghsa_rows)} GHSA rows", flush=True)

    print("Fetching Vul4J dataset...", flush=True)
    vul4j_rows = fetch_or_fallback(VUL4J_URL, "data/vul4j-eval/scan-labeled.jsonl")
    print(f"Loaded {len(vul4j_rows)} Vul4J rows", flush=True)

    print(f"Loading {MODEL}...", flush=True)
    model = AutoModel.from_pretrained(MODEL, trust_remote_code=True,
                                      torch_dtype=torch.float16).to("cuda")

    print("\n--- Running 1/3: GHSA Targeted Identity with Hybrid Criteria ---", flush=True)
    score_dataset(model, ghsa_rows, OUT_GHSA_IDENTITY)

    print("\n--- Running 2/3: GHSA Targeted Rule Swap Control ---", flush=True)
    swapped = build_rule_swap(ghsa_rows)
    score_dataset(model, ghsa_rows, OUT_GHSA_SWAP, window_overrides=swapped)

    if vul4j_rows:
        print("\n--- Running 3/3: Vul4J Targeted Identity with Hybrid Criteria ---", flush=True)
        score_dataset(model, vul4j_rows, OUT_VUL4J_IDENTITY)

    print("\nAll scoring runs complete!", flush=True)


if __name__ == "__main__":
    main()
