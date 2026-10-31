"""Fetch patch diffs from GitHub for held-out pool entries (100% leak-free).

Only selects advisories NOT present in the 68 eval advisories (labels.jsonl).
"""
import json
import time
import urllib.request
from pathlib import Path

AUDIT = Path(__file__).resolve().parent
ROOT = AUDIT.parent
OUT_DIR = AUDIT / "heldout_patches"
OUT_DIR.mkdir(parents=True, exist_ok=True)

pool = [json.loads(l) for l in open(ROOT / "data/ghsa-eval/pool.jsonl", encoding="utf-8") if l.strip()]
labels = [json.loads(l) for l in open(ROOT / "data/ghsa-eval/labels.jsonl", encoding="utf-8") if l.strip()]
eval_vuls = {r["vul_id"] for r in labels}

heldout = [r for r in pool if r["vul_id"] not in eval_vuls and r.get("patch_commit") and r.get("repo")]
print(f"Total available held-out advisories: {len(heldout)}")

downloaded = 0
for r in heldout:
    if downloaded >= 40:
        break
    repo = r["repo"]
    commit = r["patch_commit"]
    fname = f"{repo.replace('/', '_')}_{commit}.patch"
    fpath = OUT_DIR / fname
    if fpath.exists() and fpath.stat().st_size > 500:
        downloaded += 1
        continue
    
    url = f"https://github.com/{repo}/commit/{commit}.patch"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        data = urllib.request.urlopen(req, timeout=10).read()
        if len(data) > 500 and b".java" in data:
            fpath.write_bytes(data)
            downloaded += 1
            print(f"[{downloaded}/40] Downloaded {fname} ({len(data)} bytes)")
            time.sleep(0.5)
    except Exception as e:
        continue

print(f"Done! {downloaded} held-out patches saved in {OUT_DIR}")
