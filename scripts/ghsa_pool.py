"""Build a second real-world Java alert set from OSV Maven advisories.

Vul4J is one benchmark. This pulls Maven advisories from the OSV bulk export,
keeps the ones with a full GitHub fix commit, and samples across CWE families
and repositories so the result is not one project's code style.

Usage:
  python scripts/ghsa_pool.py --limit 120
  python scripts/ghsa_pool.py --limit 20 --print-only
"""
import argparse
import csv
import json
import random
import re
import sys
import urllib.request
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "ghsa-eval"
ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip"
COMMIT = re.compile(r"https://github\.com/([^/\s]+)/([^/\s#]+)/commit/([0-9a-f]{40})")

# CWE order sets the round-robin rotation, without over-weighting one family.
CWE_ORDER = ["CWE-611", "CWE-22", "CWE-78", "CWE-89", "CWE-94", "CWE-502",
             "CWE-918", "CWE-601", "CWE-79", "CWE-74", "CWE-77", "CWE-1336"]
# Maven coordinates also cover JavaScript shipped in Java projects.
NON_JAVA_REPO = re.compile(r"(?i)(jquery|bootstrap|angular|react|vue|node-|"
                           r"-js$|/js/|dompurify|ckeditor|tinymce|swagger-ui)")


def vul4j_commits():
    csv_path = ROOT / "benchmarks" / "vul4j" / "dataset" / "vul4j_dataset.csv"
    if not csv_path.exists():
        return set()
    out = set()
    for row in csv.DictReader(open(csv_path, encoding="utf-8")):
        m = re.search(r"/commit/([a-f0-9]+)$", row.get("human_patch", ""))
        if m:
            out.add(m.group(1))
    return out


def load_osv(zip_path):
    if not zip_path.exists():
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        print(f"downloading {ZIP_URL}", flush=True)
        urllib.request.urlretrieve(ZIP_URL, zip_path)
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            if name.endswith(".json"):
                yield json.loads(z.read(name))


def candidates(zip_path, skip_commits):
    out = []
    for adv in load_osv(zip_path):
        cwes = set(adv.get("database_specific", {}).get("cwe_ids") or [])
        shared = cwes & set(CWE_ORDER)
        if not shared:
            continue
        refs = [r.get("url", "") for r in adv.get("references", [])]
        hits = [COMMIT.search(u) for u in refs]
        hits = [h for h in hits if h]
        if not hits:
            continue
        repo = f"{hits[0].group(1)}/{hits[0].group(2)}"
        if NON_JAVA_REPO.search(repo):
            continue
        sha = hits[0].group(3)
        if sha in skip_commits:
            continue
        cwe = min(shared, key=CWE_ORDER.index)
        out.append({
            "vul_id": adv["id"],
            "cve_id": (adv.get("aliases") or [""])[0],
            "cwe_id": cwe,
            "cwe_ids": sorted(shared),
            "repo": repo,
            "patch_commit": sha,
            "published": (adv.get("published") or "")[:10],
            "summary": adv.get("summary", ""),
            "details": adv.get("details", ""),
        })
    return out


def select(entries, limit, per_repo, seed):
    """Round-robin across CWEs, capped per repo, newest first inside a CWE."""
    rng = random.Random(seed)
    buckets = defaultdict(list)
    for e in entries:
        buckets[e["cwe_id"]].append(e)
    for cwe, items in buckets.items():
        rng.shuffle(items)
        items.sort(key=lambda e: e["published"], reverse=True)
    picked, seen_repo = [], Counter()
    while len(picked) < limit:
        added = False
        for cwe in CWE_ORDER:
            if len(picked) >= limit:
                break
            bucket = buckets[cwe]
            while bucket:
                e = bucket.pop(0)
                if seen_repo[e["repo"]] >= per_repo:
                    continue
                picked.append(e)
                seen_repo[e["repo"]] += 1
                added = True
                break
        if not added:
            break
    return picked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", default=str(OUT / "Maven-all.zip"))
    ap.add_argument("--out", default=str(OUT / "pool.jsonl"))
    ap.add_argument("--limit", type=int, default=120)
    ap.add_argument("--per-repo", type=int, default=2)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--print-only", action="store_true")
    args = ap.parse_args()

    entries = candidates(Path(args.zip), vul4j_commits())
    print(f"{len(entries)} advisories with a fix commit and a target CWE")
    picked = select(entries, args.limit, args.per_repo, args.seed)
    repos = len({e["repo"] for e in picked})
    print(f"selected {len(picked)} entries from {repos} repos")
    for cwe, n in Counter(e["cwe_id"] for e in picked).most_common():
        print(f"  {cwe:<9} {n:>3}")
    for e in picked[:15]:
        print(f"  {e['vul_id']} {e['published']} {e['cwe_id']:<9} "
              f"{e['repo']} {e['summary'][:60]}")
    if args.print_only:
        return
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for e in picked:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"pool: {args.out}")


if __name__ == "__main__":
    sys.exit(main())
