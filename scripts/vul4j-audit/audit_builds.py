"""A1 audit: which Vul4J entries can build with Java/Maven?

Processes one repo at a time: clone -> checkout vulnerable commit ->
detect Java version from pom.xml -> attempt mvn compile -> remove clone.
No Docker (disk too constrained); uses system Java 8 + Maven 3.9.12.

Output: JSONL report at data/vul4j-audit/audit_report.jsonl
Resume: skips entries already in the report.
"""
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CSV = ROOT / "benchmarks" / "vul4j" / "dataset" / "vul4j_dataset.csv"
# Checkouts go on the root filesystem (home dir), not /tmp (small tmpfs with quota).
CHECKOUTS = Path.home() / "work" / "vul4j-checkouts"
REPORT = ROOT / "data" / "vul4j-audit" / "audit_report.jsonl"

TARGET_CWES = {"CWE-22", "CWE-78", "CWE-79", "CWE-611", "CWE-74", "CWE-77"}
PATCH_URL_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/")


def load_entries(limit=0, target_cwes=False, skip_ids=None, ids=None):
    skip_ids = skip_ids or set()
    ids = ids or set()
    entries = []
    with open(CSV, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            m = re.search(r"/commit/([a-f0-9]+)$", r["human_patch"])
            if not m:
                continue
            if r["vul_id"] in skip_ids:
                continue
            if target_cwes and r["cwe_id"] not in TARGET_CWES:
                continue
            if ids and r["vul_id"] not in ids:
                continue
            repo = r["repo_slug"]
            pm = PATCH_URL_RE.search(r["human_patch"])
            if pm:
                patch_repo = f"{pm.group(1)}/{pm.group(2)}"
                if patch_repo != repo:
                    repo = patch_repo
            entries.append({
                "vul_id": r["vul_id"],
                "cwe_id": r["cwe_id"],
                "repo": repo,
                "repo_slug": r["repo_slug"],
                "patch_commit": m.group(1),
                "compile_cmd": r["compile_cmd"].strip(),
                "failing_module": r["failing_module"].strip(),
                "build_system": r["build_system"].strip(),
            })
            if limit and len(entries) >= limit:
                break
    return entries


def git_cmd(cwd, *args):
    return subprocess.run(
        ["git"] + list(args), capture_output=True, text=True, cwd=cwd,
    )


def checkout_entry(entry, dest):
    dest.mkdir(parents=True, exist_ok=True)
    repo_dir = dest / entry["vul_id"]
    if repo_dir.exists() and (repo_dir / ".git").exists():
        res = git_cmd(repo_dir, "checkout", f"{entry['patch_commit']}^")
        if res.returncode == 0:
            return repo_dir, None
        shutil.rmtree(repo_dir, ignore_errors=True)
    try:
        res = git_cmd(
            None, "clone", f"https://github.com/{entry['repo']}.git", str(repo_dir)
        )
        if res.returncode != 0:
            res = git_cmd(
                None, "clone", f"https://github.com/{entry['repo_slug']}.git", str(repo_dir)
            )
            if res.returncode != 0:
                return None, res.stderr[-300:]
        res = git_cmd(repo_dir, "checkout", f"{entry['patch_commit']}^")
        if res.returncode != 0:
            return repo_dir, f"checkout failed: {res.stderr[-200:]}"
        return repo_dir, None
    except Exception as e:
        return None, str(e)


def detect_java_version(repo_dir, build_system):
    if build_system == "Maven":
        pom = repo_dir / "pom.xml"
        if not pom.exists():
            poms = list(repo_dir.rglob("pom.xml"))
            if poms:
                pom = poms[0]
            else:
                return None
        try:
            text = pom.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None
        m = re.search(r"<java\.version>([^<]+)</java\.version>", text)
        if m:
            val = m.group(1)
            if val.startswith("${") and val.endswith("}"):
                prop = val[2:-1]
                resolved = resolve_maven_prop(text, prop)
                return resolved or val
            return val
        for tag in ("maven.compiler.source", "maven.compiler.target"):
            m = re.search(rf"<{tag}>([^<]+)</{tag}>", text)
            if m:
                val = m.group(1)
                if val.startswith("${") and val.endswith("}"):
                    prop = val[2:-1]
                    resolved = resolve_maven_prop(text, prop)
                    return resolved or val
                return val
        m = re.search(r"<source>([^<]+)</source>\s*<target>([^<]+)</target>", text)
        if m:
            val = m.group(1)
            if val.startswith("${") and val.endswith("}"):
                prop = val[2:-1]
                resolved = resolve_maven_prop(text, prop)
                return resolved or val
            return val
        return None
    else:
        for gradle_file in repo_dir.rglob("build.gradle*"):
            try:
                text = gradle_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            m = re.search(r"sourceCompatibility\s*=\s*['\"]([^'\"]+)['\"]", text)
            if m:
                return m.group(1)
            m = re.search(r"JavaVersion\.VERSION_(\d+)", text)
            if m:
                return m.group(1)
        return None


def resolve_maven_prop(text, prop_name):
    m = re.search(rf"<{re.escape(prop_name)}>([^<]+)</{re.escape(prop_name)}>", text)
    return m.group(1) if m else None


def run_build(repo_dir, entry):
    """Run the compile command. Returns (success, stderr_tail)."""
    cmd = entry["compile_cmd"]
    # Replace $VUL4J_GIT if present
    cmd = cmd.replace("$VUL4J_GIT", str(repo_dir))
    # For multi-module, run from repo root
    try:
        res = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            cwd=str(repo_dir), timeout=600,
        )
        return res.returncode == 0, (res.stdout + res.stderr)[-800:] if res.returncode else ""
    except subprocess.TimeoutExpired:
        return False, "timeout (15 min)"
    except Exception as e:
        return False, str(e)


def free_space_mb():
    st = os.statvfs("/")
    return st.f_bavail * st.f_frsize // (1024 * 1024)


def arg_value(flag):
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 0
    target_only = "--target-cwes" in sys.argv
    force = "--force" in sys.argv
    ids_arg = arg_value("--ids")
    ids = set(ids_arg.split(",")) if ids_arg else None
    report = Path(arg_value("--report") or REPORT)

    # Load already-processed IDs for resume
    skip_ids = set()
    if report.exists() and not force:
        with open(report, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                    skip_ids.add(r["vul_id"])
                except Exception:
                    pass

    entries = load_entries(limit, target_cwes=target_only, skip_ids=skip_ids, ids=ids)
    if not entries:
        print("No new entries to process.")
        return

    print(f"Audit: {len(entries)} new entries (free disk: {free_space_mb()}MB)")

    CHECKOUTS.mkdir(parents=True, exist_ok=True)
    report.parent.mkdir(parents=True, exist_ok=True)

    results = []
    for i, entry in enumerate(entries):
        print(f"\n[{i+1}/{len(entries)}] {entry['vul_id']} {entry['repo']} ({entry['build_system']}) free={free_space_mb()}MB")

        if free_space_mb() < 150:
            print(f"  SKIP: insufficient disk ({free_space_mb()}MB)")
            result = dict(entry)
            result["cloned"] = False
            result["checked_out"] = False
            result["java_version"] = None
            result["build_success"] = "skipped-disk"
            result["build_error"] = "insufficient disk space"
            result["checkout_error"] = None
            results.append(result)
            with open(report, "a", encoding="utf-8") as f:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")
            continue

        result = dict(entry)
        result["cloned"] = False
        result["checked_out"] = False
        result["java_version"] = None
        result["build_success"] = None
        result["build_error"] = None
        result["checkout_error"] = None

        repo_dir, err = checkout_entry(entry, CHECKOUTS)
        if err:
            result["checkout_error"] = err
            result["build_error"] = "clone or checkout failed"
            results.append(result)
            with open(report, "a", encoding="utf-8") as f:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")
            print(f"  FAILED: {err[:200]}")
            continue
        result["cloned"] = True

        res = git_cmd(repo_dir, "rev-parse", "HEAD")
        if res.returncode == 0:
            result["checked_out"] = True
            result["commit"] = res.stdout.strip()[:10]

        java_version = detect_java_version(repo_dir, entry["build_system"])
        result["java_version"] = java_version
        print(f"  Java version: {java_version}")

        if free_space_mb() < 200:
            print(f"  SKIP build: insufficient disk ({free_space_mb()}MB)")
            result["build_success"] = "skipped-disk"
            result["build_error"] = "insufficient disk space for build"
        else:
            success, error = run_build(repo_dir, entry)
            result["build_success"] = success
            result["build_error"] = error if not success else None
            print(f"  Build: {'OK' if success else 'FAILED'} {error[:120] if error else ''}")

        results.append(result)

        # Write result incrementally (resume support)
        with open(report, "a", encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")

        # Aggressive cleanup
        shutil.rmtree(repo_dir, ignore_errors=True)

    # Summary
    built = sum(1 for r in results if r["build_success"] is True)
    failed = sum(1 for r in results if r["build_success"] is False)
    skipped = sum(1 for r in results if r["build_success"] in ("pending", "skipped-disk"))
    clone_fail = sum(1 for r in results if not r["cloned"])
    print(f"\n=== A1 Audit Summary (this run) ===")
    print(f"  Entries processed: {len(results)}")
    print(f"  Builds OK: {built}")
    print(f"  Builds FAILED: {failed}")
    print(f"  Skipped (disk): {skipped}")
    print(f"  Clone/checkout failed: {clone_fail}")
    print(f"  Report: {report}")


if __name__ == "__main__":
    main()
