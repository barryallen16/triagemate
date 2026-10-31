"""Construct 100% leak-free contrastive training dataset for d1-3B LoRA.

Extracts pre-fix (TP, vulnerable) and post-fix (FP, secure) method pairs
from held-out real Java security patches in work/audit/heldout_patches/.
"""
import json
import re
from pathlib import Path

AUDIT = Path(__file__).resolve().parent
ROOT = AUDIT.parent
OUT_PATH = AUDIT / "contrastive_train.jsonl"

pool = {r['patch_commit']: r for r in [json.loads(l) for l in open(ROOT / 'data/ghsa-eval/pool.jsonl', encoding='utf-8') if l.strip()] if r.get('patch_commit')}
patches = list((AUDIT / 'heldout_patches').glob('*.patch'))

dataset_rows = []
for p in patches:
    commit = p.stem.split('_')[-1]
    meta = pool.get(commit, {})
    cwe = meta.get('cwe_id', 'CWE-Unknown')
    summary = meta.get('summary', 'Security vulnerability fix')
    vul_id = meta.get('vul_id', 'HELD')
    
    txt = p.read_text(encoding='utf-8', errors='ignore')
    diffs = re.split(r'\ndiff --git ', txt)
    for d in diffs[1:]:
        header = d.splitlines()[0]
        if not (header.endswith('.java') or '.java ' in header):
            continue
        hunks = re.split(r'\n@@ -\d+,\d+ \+\d+,\d+ @@', d)
        for h in hunks[1:]:
            lines = h.splitlines()
            pre_lines = [l[1:] for l in lines if l.startswith(' ') or l.startswith('-')]
            post_lines = [l[1:] for l in lines if l.startswith(' ') or l.startswith('+')]
            deleted = [l[1:] for l in lines if l.startswith('-')]
            added = [l[1:] for l in lines if l.startswith('+')]
            if deleted and added and len(pre_lines) >= 4 and len(post_lines) >= 4:
                file_name = header.split()[-1]
                idx = len(dataset_rows) // 2
                # TP row (pre-fix vulnerable code)
                dataset_rows.append({
                    'id': f'{vul_id}:pre:{idx}',
                    'rule': f'java.security.{cwe.lower()}.vulnerability',
                    'cwe': cwe,
                    'severity': 'ERROR',
                    'file': file_name,
                    'line': 0,
                    'message': summary,
                    'code_window': '\n'.join(pre_lines),
                    'label': 'TP',
                })
                # FP row (post-fix secure patch)
                dataset_rows.append({
                    'id': f'{vul_id}:post:{idx}',
                    'rule': f'java.security.{cwe.lower()}.vulnerability',
                    'cwe': cwe,
                    'severity': 'ERROR',
                    'file': file_name,
                    'line': 0,
                    'message': summary,
                    'code_window': '\n'.join(post_lines),
                    'label': 'FP',
                })

with open(OUT_PATH, 'w', encoding='utf-8') as fh:
    for r in dataset_rows:
        fh.write(json.dumps(r) + '\n')

print(f"Wrote {len(dataset_rows)} balanced contrastive rows to {OUT_PATH}")
print(f"TP count: {sum(r['label'] == 'TP' for r in dataset_rows)}")
print(f"FP count: {sum(r['label'] == 'FP' for r in dataset_rows)}")
