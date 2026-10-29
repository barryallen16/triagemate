"""A3: scan vulnerable Vul4J checkouts and label Semgrep findings.

Reads the A1 audit report, checks out the parent of the fix commit, runs
Semgrep, and labels a finding TP when it sits on a line changed by the fix or
in a method the fix changes. Rule CWE metadata is stored but does not decide
the label.

Usage:
  python scripts/vul4j_scan.py
  python scripts/vul4j_scan.py --entries VUL4J-41,VUL4J-59 --force
  python scripts/vul4j_scan.py --all-vul4j --all-cwes --changed-only
"""
import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from triage.cli import fallback_window, heuristic_score
from triage.dataset import build_window, enclosing_method, method_ranges, rule_cwes

AUDIT = ROOT / "data" / "vul4j-audit" / "audit_report.jsonl"
CSV = ROOT / "benchmarks" / "vul4j" / "dataset" / "vul4j_dataset.csv"
OUT = ROOT / "data" / "vul4j-eval"
SCANS = OUT / "scans"
ROWS = OUT / "rows"
CHECKOUTS = Path.home() / "work" / "vul4j-scan-checkouts"
TARGET_CWES = {"CWE-22", "CWE-78", "CWE-79", "CWE-611", "CWE-74", "CWE-77"}
RULES = ["--config", "p/default", "--config", "p/security-audit",
         "--config", "p/owasp-top-ten"]
FAST_RULES = ["--config", "p/security-audit", "--config", "p/owasp-top-ten"]


def git(cwd, *args, timeout=600):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                          text=True, timeout=timeout)


def load_entries(audit_path, ids=None, target_cwes=True):
    latest = {}
    for line in open(audit_path, encoding="utf-8"):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("vul_id"):
            latest[r["vul_id"]] = r
    entries = []
    for r in latest.values():
        if r.get("build_success") is not True:
            continue
        if target_cwes and r.get("cwe_id") not in TARGET_CWES:
            continue
        if ids and r["vul_id"] not in ids:
            continue
        entries.append(r)
    return sorted(entries, key=lambda r: int(r["vul_id"].split("-")[1]))


def load_all_entries(csv_path, ids=None):
    """Every Vul4J entry with a patch commit, build result not required.

    Semgrep reads source, so a checkout is enough to scan an entry. The gate
    keeps the build flag separately and does not claim these all build.
    """
    entries = []
    with open(csv_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if ids and row["vul_id"] not in ids:
                continue
            match = re.search(r"/commit/([a-f0-9]+)$", row["human_patch"])
            if not match:
                continue
            repo = row["repo_slug"]
            patch_repo = re.search(r"github\.com/([^/]+/[^/]+)/commit/",
                                   row["human_patch"])
            if patch_repo:
                repo = patch_repo.group(1)
            entries.append({
                "vul_id": row["vul_id"],
                "cwe_id": row["cwe_id"],
                "repo": repo,
                "repo_slug": row["repo_slug"],
                "patch_commit": match.group(1),
                "build_success": "unverified",
            })
    return sorted(entries, key=lambda r: int(r["vul_id"].split("-")[1]))


def resolve_patch(repo, patch):
    if len(patch) == 40:
        return patch
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/commits/{patch}",
        headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)["sha"]


def checkout(entry, force=False):
    dest = CHECKOUTS / entry["vul_id"]
    if dest.exists():
        if not force:
            return dest, None
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.mkdir()
    patch = entry["patch_commit"]
    try:
        patch = resolve_patch(entry["repo"], patch)
    except (OSError, ValueError, KeyError) as exc:
        shutil.rmtree(dest, ignore_errors=True)
        return None, f"could not resolve patch commit {patch}: {exc}"
    entry["patch_commit"] = patch
    # Depth 2 gets the fix commit and its parent without a full clone.
    res = git(dest, "init", "-q")
    res = git(dest, "remote", "add", "origin", f"https://github.com/{entry['repo']}.git")
    res = git(dest, "fetch", "-q", "--depth", "2", "origin", patch, timeout=1800)
    if res.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        return None, f"fetch failed: {res.stderr[-300:]}"
    res = git(dest, "checkout", "-q", f"{patch}^")
    if res.returncode != 0:
        return dest, f"checkout failed: {res.stderr[-300:]}"
    return dest, None


HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def diff_hunks(repo, patch, paths=None):
    """Map changed Java files to old-side line numbers, expanded by two lines."""
    res = git(repo, "-c", "core.quotepath=false", "diff", "--unified=0",
              f"{patch}^", patch, *(["--"] + list(paths) if paths else []))
    if res.returncode != 0:
        return {}
    touched = {}
    current = None
    for line in res.stdout.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            if current.endswith(".java"):
                touched.setdefault((repo / current).resolve(), set())
            else:
                current = None
        elif current and line.startswith("@@"):
            m = HUNK_RE.match(line)
            if not m:
                continue
            start, count = int(m.group(1)), int(m.group(2) or 1)
            if count == 0:
                lines = {start, start + 1}
            else:
                lines = set(range(start, start + count))
            bucket = touched[(repo / current).resolve()]
            for n in lines:
                bucket.update(range(n - 2, n + 3))
    return touched


def scan(repo, out_file, timeout, changed_only=False, changed_files=None):
    out_file.parent.mkdir(parents=True, exist_ok=True)
    if changed_only:
        targets = sorted(p for p in (changed_files or [])
                         if not is_test_source(repo_relative(p, repo)))
    else:
        targets = [repo]
    if not targets:
        out_file.write_text(json.dumps({"results": []}), encoding="utf-8")
        return 0.0, None
    cmd = ["semgrep", *(FAST_RULES if changed_only else RULES),
           "--json", "--quiet", "--jobs", "1", "--timeout", "30",
           "--max-target-bytes", "2000000", "--metrics", "off",
           "-o", str(out_file), *(str(p) for p in targets)]
    started = time.time()
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"semgrep timed out after {timeout}s"
    if not out_file.exists():
        return None, "semgrep wrote no output"
    return time.time() - started, None


def source_path(raw, repo):
    path = Path(raw)
    if path.is_absolute():
        return path
    candidate = repo / path
    return candidate if candidate.exists() else Path.cwd() / path


def repo_relative(src, repo):
    """Stable path for IDs: repo-relative when possible, basename otherwise."""
    try:
        return str(src.resolve().relative_to(Path(repo).resolve()))
    except ValueError:
        return src.name


TEST_SOURCE = ("/src/test/", "/src/testFixtures/", "/src/it/", "/test/java/")


def is_test_source(path):
    """Test sources are not the vulnerable production code.

    Vul4J patches often add a regression test next to the fix, so a rule hit
    there would otherwise be labeled TP just for overlapping the patch.
    """
    return any(part in "/" + str(path).replace("\\", "/") for part in TEST_SOURCE)


def rows_for(entry, repo, touched, scan_file):
    data = json.loads(scan_file.read_text(encoding="utf-8"))
    entry_cwe = entry["cwe_id"]
    rows = []
    for f in data.get("results", []):
        src = source_path(f["path"], repo)
        if src.suffix != ".java" or not src.exists():
            continue
        rel = repo_relative(src, repo)
        if is_test_source(rel):
            continue
        extra = f.get("extra", {})
        meta = extra.get("metadata", {})
        cwes = rule_cwes(meta)
        line = f["start"]["line"]
        changed = touched.get(src.resolve(), set())
        text = src.read_text(encoding="utf-8", errors="replace")

        hit = line in changed
        if not hit and changed:
            method = enclosing_method(method_ranges(text), line)
            hit = bool(method) and any(method[1] <= n <= method[2] for n in changed)
        label = "TP" if hit else "FP"

        got = build_window(text, line, None, juliet=False)
        if got:
            method_name, window = got
        else:
            method_name, window = "", fallback_window(src, line)
        p_tp, _ = heuristic_score({"severity": extra.get("severity", "WARNING"),
                                   "message": extra.get("message", "")})
        rows.append({
            "id": f"{entry['vul_id']}:{f['check_id']}:{rel}:{line}",
            "vul_id": entry["vul_id"],
            "label": label,
            "p_tp": p_tp,
            "rule": f["check_id"],
            "cwe": entry_cwe,
            "path": rel,
            "file": str(src),
            "line": line,
            "method": method_name,
            "code_window": window,
            "message": extra.get("message", ""),
            "severity": extra.get("severity", "WARNING"),
            "changed_file": src.resolve() in touched,
            "finding_cwes": sorted(cwes),
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", default=str(AUDIT))
    ap.add_argument("--entries", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--relabel", action="store_true",
                    help="reuse cached Semgrep scans, recompute labels only")
    ap.add_argument("--changed-only", action="store_true",
                    help="scan only changed Java files with security Semgrep packs")
    ap.add_argument("--all-cwes", action="store_true",
                    help="include buildable entries outside the target CWE set")
    ap.add_argument("--all-vul4j", action="store_true",
                    help="scan every CSV entry with a checkout, build not required")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args()

    ids = {x.strip() for x in args.entries.split(",") if x.strip()}
    if args.all_vul4j:
        entries = load_all_entries(CSV, ids)
    else:
        entries = load_entries(Path(args.audit), ids, target_cwes=not args.all_cwes)
    if args.limit:
        entries = entries[:args.limit]
    if not entries:
        sys.exit("no entries selected")

    SCANS.mkdir(parents=True, exist_ok=True)
    ROWS.mkdir(parents=True, exist_ok=True)
    CHECKOUTS.mkdir(parents=True, exist_ok=True)

    order = []
    for entry in entries:
        vid = entry["vul_id"]
        order.append(vid)
        row_file = ROWS / f"{vid}.jsonl"
        if row_file.exists() and not args.force and not args.relabel:
            print(f"{vid}: cached {sum(1 for _ in open(row_file))} rows")
            continue

        print(f"\n{vid} {entry['repo']} {entry['cwe_id']}", flush=True)
        repo, err = checkout(entry, force=args.force)
        if err:
            print(f"  {err}")
            if row_file.exists():
                row_file.unlink()
            (SCANS / f"{vid}.meta.json").write_text(
                json.dumps({"vul_id": vid, "error": err}, indent=2))
            continue

        changed = diff_hunks(repo, entry["patch_commit"])
        scan_file = SCANS / f"{vid}.json"
        if args.relabel and scan_file.exists() and not args.force:
            print(f"  reusing scan {scan_file.name}", flush=True)
            elapsed, err = 0.0, None
        else:
            elapsed, err = scan(repo, scan_file, args.timeout,
                                changed_only=args.changed_only,
                                changed_files=changed if args.changed_only else None)
        if err:
            print(f"  {err}")
            if row_file.exists():
                row_file.unlink()
            (SCANS / f"{vid}.meta.json").write_text(
                json.dumps({"vul_id": vid, "error": err, "changed_files": len(changed)},
                           indent=2))
        else:
            rows = rows_for(entry, repo, changed, scan_file)
            with open(row_file, "w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            tp = sum(1 for r in rows if r["label"] == "TP")
            print(f"  {len(rows)} findings, {tp} TP, {len(rows)-tp} FP, "
                  f"{len(changed)} changed files, {elapsed:.0f}s")
            (SCANS / f"{vid}.meta.json").write_text(json.dumps({
                "vul_id": vid, "repo": entry["repo"],
                "patch_commit": entry["patch_commit"], "cwe": entry["cwe_id"],
                "scan_scope": "changed_java_files" if args.changed_only else "repository",
                "configs": FAST_RULES if args.changed_only else RULES,
                "findings": len(rows), "tp": tp, "fp": len(rows) - tp,
                "changed_files": sorted(str(p) for p in changed),
                "seconds": round(elapsed, 1),
            }, indent=2))

        if not args.keep:
            shutil.rmtree(repo, ignore_errors=True)

    all_rows = []
    for row_file in sorted(ROWS.glob("VUL4J-*.jsonl"),
                           key=lambda p: int(p.stem.split("-")[1])):
        all_rows += [json.loads(line) for line in open(row_file, encoding="utf-8")]
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "scan-labeled.jsonl", "w", encoding="utf-8") as fh:
        for row in all_rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    by_entry = {}
    for row in all_rows:
        by_entry.setdefault(row["vul_id"], [0, 0])
        by_entry[row["vul_id"]][0 if row["label"] == "TP" else 1] += 1
    print("\n=== A3 scan summary ===")
    for vid in order:
        tp, fp = by_entry.get(vid, [0, 0])
        print(f"  {vid}: {tp} TP, {fp} FP")
    print(f"  total: {len(all_rows)} findings")
    print(f"  labeled: {OUT / 'scan-labeled.jsonl'}")


if __name__ == "__main__":
    main()
