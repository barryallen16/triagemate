"""Evaluate TriageMate on real vul4j vulnerabilities.

Checks out vulnerable versions of selected vul4j entries, runs Semgrep, and
writes findings for triage scoring. Labels are derived from the known
vulnerability CWE and the human patch commit.
"""
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV = ROOT / "benchmarks" / "vul4j" / "dataset" / "vul4j_dataset.csv"
OUT = ROOT / "data" / "vul4j-eval"

# CWEs that Semgrep's security rules cover - these are the ones we can label.
TARGET_CWES = {"CWE-22", "CWE-78", "CWE-79", "CWE-611", "CWE-74", "CWE-77"}

# Map CWE to Semgrep rule families for labeling.
CWE_TO_RULE = {
    "CWE-22": "path-traversal",
    "CWE-78": "command-injection",
    "CWE-79": "xss",
    "CWE-611": "xml-external-entity",
    "CWE-74": "incomplete-neutralization",
    "CWE-77": "command-injection",
}


def load_entries(limit=0):
    entries = []
    with open(CSV, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cwe = r["cwe_id"].strip()
            if cwe not in TARGET_CWES:
                continue
            m = re.search(r"/commit/([a-f0-9]+)$", r["human_patch"])
            if not m:
                continue
            entries.append({
                "vul_id": r["vul_id"],
                "cwe": cwe,
                "cwe_name": r["cwe_name"],
                "repo": r["repo_slug"],
                "patch_commit": m.group(1),
                "compile_cmd": r["compile_cmd"],
                "failing_module": r["failing_module"],
            })
            if limit and len(entries) >= limit:
                break
    return entries


def checkout_vulnerable(entry, dest):
    """Clone repo and checkout parent of the patch commit (vulnerable version)."""
    dest.mkdir(parents=True, exist_ok=True)
    repo_dir = dest / entry["vul_id"]
    if repo_dir.exists():
        return repo_dir
    # Full clone (needed to reach historical patch commits)
    subprocess.run(
        ["git", "clone", f"https://github.com/{entry['repo']}.git", str(repo_dir)],
        check=True, capture_output=True,
    )
    # Checkout parent of patch commit (vulnerable version)
    subprocess.run(
        ["git", "-C", str(repo_dir), "checkout", f"{entry['patch_commit']}^"],
        check=True, capture_output=True,
    )
    return repo_dir


def run_semgrep(repo_dir, out_file):
    """Run semgrep security rules on the repo, write JSON results."""
    cmd = [
        "semgrep", "--config", "p/security-audit", "--config", "p/owasp-top-ten",
        "--json", "--quiet", "--timeout", "60",
        "--max-target-bytes", "2000000", "--metrics", "off",
        "-o", str(out_file), str(repo_dir),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if out_file.exists():
        return json.loads(out_file.read_text())
    return {"results": []}


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    entries = load_entries(limit)
    OUT.mkdir(parents=True, exist_ok=True)

    for entry in entries:
        print(f"=== {entry['vul_id']} ({entry['cwe']}) {entry['repo']} ===")
        try:
            repo_dir = checkout_vulnerable(entry, OUT / "checkouts")
            scan_file = OUT / "scans" / f"{entry['vul_id']}.json"
            scan_file.parent.mkdir(parents=True, exist_ok=True)
            scan = run_semgrep(repo_dir, scan_file)
            n = len(scan.get("results", []))
            print(f"  Semgrep findings: {n}")
            # Save entry metadata alongside scan
            meta_file = OUT / "scans" / f"{entry['vul_id']}.meta.json"
            meta_file.write_text(json.dumps(entry, indent=2))
        except subprocess.CalledProcessError as e:
            print(f"  FAILED: {e.stderr[-500:] if e.stderr else e}")
        except Exception as e:
            print(f"  ERROR: {e}")


if __name__ == "__main__":
    main()
