"""Scan a pool of GitHub advisory fix commits for the second eval set.

Reuses the Vul4J scanner's checkout, diff, Semgrep and label code on a generic
entry list, so both sets share one label rule. Writes rows under
data/ghsa-eval/ and a combined labels.jsonl for the gate.

Usage:
  python scripts/ghsa_scan.py --limit 10
  python scripts/ghsa_scan.py --force --timeout 600
"""
import argparse
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import vul4j_scan as v

OUT = ROOT / "data" / "ghsa-eval"
POOL = OUT / "pool.jsonl"
SCANS = OUT / "scans"
ROWS = OUT / "rows"
CHECKOUTS = Path.home() / "work" / "ghsa-scan-checkouts"
v.CHECKOUTS = CHECKOUTS


def natural(vid):
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", vid)]


def test_module(path):
    """Drop test modules that are not under src/test, e.g. hugegraph-test.

    The shared is_test_source rule only knows the standard Maven layout, and
    this advisory set often adds tests in modules named *-test.
    """
    parts = Path(path).parts[:-1]
    return any(p in ("test", "tests", "it") or p.endswith(("-test", "-tests"))
               for p in parts)


def partial_checkout(entry, force=False):
    """Fetch the fix commit without blobs and materialize only old .java files.

    A full depth-2 fetch of a monorepo costs hundreds of MB. The scan only
    reads changed Java files, so fetch trees and lazily pull those blobs.
    Returns the changed Java paths so wide patches can be skipped before any
    blob is fetched.
    """
    dest = CHECKOUTS / entry["vul_id"]
    if dest.exists():
        if not force:
            return dest, None, None
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.mkdir()
    sha = entry["patch_commit"]
    v.git(dest, "init", "-q")
    v.git(dest, "remote", "add", "origin",
          f"https://github.com/{entry['repo']}.git")
    res = v.git(dest, "fetch", "-q", "--depth", "2", "--filter=blob:none",
                "origin", sha, timeout=1800)
    if res.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        return None, None, f"fetch failed: {res.stderr[-300:]}"
    res = v.git(dest, "-c", "core.quotepath=false", "diff", "--name-only",
                f"{sha}^", sha, "--", "*.java")
    if res.returncode != 0:
        return dest, None, f"diff failed: {res.stderr[-300:]}"
    paths = [line for line in res.stdout.splitlines() if line.strip()]
    if paths:
        # Files added by the fix have no old-side content to scan.
        res = v.git(dest, "-c", "core.quotepath=false", "ls-tree", "-r",
                    "--name-only", "-z", f"{sha}^", "--", *paths)
        existing = set(res.stdout.split("\0"))
        paths = [p for p in paths if p in existing]
    return dest, paths, None


def materialize(dest, sha, paths):
    res = v.git(dest, "checkout", "-q", f"{sha}^", "--", *paths, timeout=1800)
    if res.returncode != 0:
        return f"checkout failed: {res.stderr[-300:]}"
    return None


def read_jsonl(path):
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default=str(POOL))
    ap.add_argument("--ids", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--max-java-files", type=int, default=25)
    ap.add_argument("--full-rules", action="store_true",
                    help="add p/default alongside the two security packs")
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()
    if args.full_rules:
        v.FAST_RULES = v.RULES

    entries = read_jsonl(Path(args.pool))
    ids = {x.strip() for x in args.ids.split(",") if x.strip()}
    if ids:
        entries = [e for e in entries if e["vul_id"] in ids]
    if args.limit:
        entries = entries[:args.limit]
    if not entries:
        sys.exit("no entries selected")

    for d in (SCANS, ROWS):
        d.mkdir(parents=True, exist_ok=True)

    for entry in entries:
        vid = entry["vul_id"]
        row_file = ROWS / f"{vid}.jsonl"
        if row_file.exists() and not args.force:
            print(f"{vid}: cached {sum(1 for _ in open(row_file))} rows")
            continue

        print(f"\n{vid} {entry['repo']} {entry['cwe_id']}", flush=True)
        repo, java_files, err = partial_checkout(entry, force=args.force)
        if err:
            print(f"  {err}")
            (SCANS / f"{vid}.meta.json").write_text(json.dumps(
                {"vul_id": vid, "repo": entry["repo"], "error": err}, indent=2))
            continue

        if not java_files:
            print("  no changed java files")
            (SCANS / f"{vid}.meta.json").write_text(json.dumps(
                {"vul_id": vid, "repo": entry["repo"], "error": "no_java_files"},
                indent=2))
        elif len(java_files) > args.max_java_files:
            print(f"  patch too wide: {len(java_files)} java files")
            (SCANS / f"{vid}.meta.json").write_text(json.dumps(
                {"vul_id": vid, "repo": entry["repo"], "error": "patch_too_wide",
                 "java_files": len(java_files)}, indent=2))
        else:
            err = materialize(repo, entry["patch_commit"], java_files)
            if err:
                print(f"  {err}")
                (SCANS / f"{vid}.meta.json").write_text(json.dumps(
                    {"vul_id": vid, "repo": entry["repo"], "error": err}, indent=2))
                shutil.rmtree(repo, ignore_errors=True)
                continue
            changed = v.diff_hunks(repo, entry["patch_commit"], paths=java_files)
            scan_file = SCANS / f"{vid}.json"
            elapsed, err = v.scan(repo, scan_file, args.timeout,
                                  changed_only=True, changed_files=changed)
            if err:
                print(f"  {err}")
                (SCANS / f"{vid}.meta.json").write_text(json.dumps(
                    {"vul_id": vid, "repo": entry["repo"], "error": err}, indent=2))
            else:
                rows = [r for r in v.rows_for(entry, repo, changed, scan_file)
                        if not test_module(r["path"])]
                with open(row_file, "w", encoding="utf-8") as fh:
                    for row in rows:
                        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                tp = sum(1 for r in rows if r["label"] == "TP")
                print(f"  {len(rows)} findings, {tp} TP, {len(rows) - tp} FP, "
                      f"{len(java_files)} changed java files, {elapsed:.0f}s")
                (SCANS / f"{vid}.meta.json").write_text(json.dumps({
                    "vul_id": vid, "repo": entry["repo"],
                    "patch_commit": entry["patch_commit"], "cwe": entry["cwe_id"],
                    "summary": entry.get("summary", ""),
                    "scan_scope": "changed_java_files",
                    "configs": v.FAST_RULES,
                    "findings": len(rows), "tp": tp, "fp": len(rows) - tp,
                    "changed_files": sorted(str(p) for p in changed),
                    "seconds": round(elapsed, 1),
                }, indent=2))

        if not args.keep:
            shutil.rmtree(repo, ignore_errors=True)

    all_rows = []
    for row_file in sorted(ROWS.glob("GHSA-*.jsonl"), key=lambda p: natural(p.stem)):
        all_rows += [r for r in read_jsonl(row_file) if not test_module(r["path"])]
    with open(OUT / "labels.jsonl", "w", encoding="utf-8") as fh:
        for row in all_rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    by_entry = {}
    for row in all_rows:
        by_entry.setdefault(row["vul_id"], [0, 0])
        by_entry[row["vul_id"]][0 if row["label"] == "TP" else 1] += 1
    tp = sum(r["label"] == "TP" for r in all_rows)
    print(f"\n=== GHSA scan summary ===")
    for vid in sorted(by_entry, key=natural):
        t, f = by_entry[vid]
        print(f"  {vid}: {t} TP, {f} FP")
    print(f"  total: {len(all_rows)} findings, {tp} TP, {len(all_rows) - tp} FP, "
          f"{len(by_entry)} entries")
    print(f"  labeled: {OUT / 'labels.jsonl'}")


if __name__ == "__main__":
    main()
