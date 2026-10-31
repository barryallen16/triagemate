"""Re-derive labels from the upstream patches, without the scanner.

For every row, fetch the fix patch for its entry and check whether the finding
line falls in a changed hunk (old side, plus the same two lines of context).
Compare with the stored label to separate hunk hits from method-only hits.
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

AUDIT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AUDIT_DIR.parent
CACHE = AUDIT_DIR / "patches"
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def fetch(repo, sha):
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / f"{repo.replace('/', '_')}_{sha}.patch"
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace")
    url = f"https://github.com/{repo}/commit/{sha}.patch"
    req = urllib.request.Request(url, headers={"User-Agent": "triagemate-audit"})
    text = urllib.request.urlopen(req, timeout=90).read().decode("utf-8", "replace")
    path.write_text(text, encoding="utf-8")
    return text


def changed_lines(patch):
    """{repo-relative path: set(old-side line numbers, expanded by two)}"""
    out = {}
    current = None
    old = 0
    in_hunk = False
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            current = None
            in_hunk = False
            continue
        if not in_hunk and line.startswith("+++ "):
            raw = line[4:].strip()
            current = None
            if raw.startswith("b/") and raw.endswith(".java"):
                current = raw[2:]
                out.setdefault(current, set())
            continue
        if line.startswith("@@"):
            m = HUNK.match(line)
            if m and current is not None:
                old = int(m.group(1))
                in_hunk = True
            continue
        if current is None or not in_hunk or not line:
            continue
        if line[0] == "-":
            out[current].update(range(old - 2, old + 3))
            old += 1
        elif line[0] == " ":
            old += 1
    return out


def main():
    labels_path = REPO_ROOT / "data" / "ghsa-eval" / "labels.jsonl"
    if not labels_path.exists():
        labels_path = REPO_ROOT / "work" / "data" / "ghsa-eval" / "labels.jsonl"
    rows = read(str(labels_path))
    by_entry = {}
    for row in rows:
        by_entry.setdefault(row["vul_id"], []).append(row)
    results, failures = [], []
    for vid, erows in sorted(by_entry.items()):
        meta = json.loads(Path(f"{ROOT}/data/ghsa-eval/scans/{vid}.meta.json").read_text())
        repo, sha = meta["repo"], meta["patch_commit"]
        try:
            hunks = changed_lines(fetch(repo, sha))
        except Exception as exc:  # noqa: BLE001
            failures.append((vid, str(exc)))
            continue
        for row in erows:
            hit = row["line"] in hunks.get(row["path"], set())
            results.append({
                "id": row["id"], "vul_id": vid, "path": row["path"],
                "line": row["line"], "stored": row["label"],
                "hunk_tp": hit, "file_in_patch": row["path"] in hunks,
            })
    (AUDIT_DIR / "relabel.json").write_text(json.dumps(results, indent=2))
    stored_tp = [r for r in results if r["stored"] == "TP"]
    print(f"rows re-derived {len(results)}  entries {len(by_entry)}  fetch failures {len(failures)}")
    print(f"stored TP {len(stored_tp)}")
    print(f"  hunk TP {sum(r['hunk_tp'] for r in stored_tp)}")
    print(f"  method-only TP {sum(not r['hunk_tp'] for r in stored_tp)}")
    bad = [r for r in results if r["stored"] == "FP" and r["hunk_tp"]]
    print(f"stored FP that are hunk hits (should be 0): {len(bad)}")
    not_in_patch = [r for r in results if not r["file_in_patch"]]
    print(f"rows whose file is absent from the patch: {len(not_in_patch)}")
    if failures:
        print("failures:", failures[:5])
    print("\nmethod-only TP by entry:")
    counts = {}
    for r in stored_tp:
        if not r["hunk_tp"]:
            counts[r["vul_id"]] = counts.get(r["vul_id"], 0) + 1
    for vid, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {vid}: {n}")
    if bad:
        for r in bad[:10]:
            print("  FP hunk hit:", r)


if __name__ == "__main__":
    sys.exit(main())
