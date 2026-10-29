"""Phase 4 checker: does a patch compile, kill the warning, and add no new ones?

Usage:
  python -m triage.verify --project . --file src/Foo.java \
      --original /tmp/Foo.java --rule java.lang.security.audit.sqli.jdbc-sqli

The patched and original files must both exist. `--mode javac` takes a classpath.
"""
import argparse
import json
import subprocess
from collections import Counter
import sys
import tempfile
from pathlib import Path

RULES = ["--config", "p/default", "--config", "p/security-audit",
         "--config", "p/owasp-top-ten"]


def compile_maven(project):
    try:
        p = subprocess.run(["mvn", "-q", "test-compile"], cwd=project,
                           capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)[-2000:]
    return p.returncode == 0, (p.stdout + p.stderr)[-2000:]


def compile_javac(files, classpath):
    cmd = ["javac", "-cp", classpath, *files]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)[-2000:]
    return p.returncode == 0, (p.stdout + p.stderr)[-2000:]


def scan(path):
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "f.json"
        try:
            p = subprocess.run(["semgrep", *RULES, "--json", "--quiet", "--metrics", "off",
                                "-o", str(out), str(path)], capture_output=True, text=True,
                               timeout=600)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"Semgrep failed for {path}: {exc}") from exc
        if p.returncode != 0 or not out.exists():
            raise RuntimeError(f"Semgrep failed for {path}: {(p.stderr or p.stdout)[-2000:]}")
        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"invalid Semgrep output for {path}: {exc}") from exc
    return Counter(r["check_id"] for r in data.get("results", []))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--file", required=True, help="patched file, relative to project")
    ap.add_argument("--original", required=True, help="unpatched copy, relative to project")
    ap.add_argument("--rule", required=True, help="the warning the patch should remove")
    ap.add_argument("--mode", choices=["maven", "javac"], default="maven")
    ap.add_argument("--classpath", default="")
    args = ap.parse_args()
    project = Path(args.project).resolve()
    target = project / args.file
    original = project / args.original
    if not target.is_file():
        sys.exit(f"no such patched file: {target}")
    if not original.is_file():
        sys.exit(f"no such original file: {original}")

    if args.mode == "maven":
        ok, log = compile_maven(project)
    else:
        ok, log = compile_javac([str(target)], args.classpath)
    try:
        after = scan(target)
        before = scan(original)
    except RuntimeError as exc:
        sys.exit(str(exc))
    new_rules = sorted(f"{rule} (+{after[rule] - before[rule]})"
                       for rule in after if after[rule] > before[rule])
    result = {
        "compiles": ok,
        "compile_log": log if not ok else "",
        "rule_before": before[args.rule] > 0,
        "rule_after": after[args.rule] > 0,
        "new_rules": new_rules,
        "ok": bool(ok and before[args.rule] > 0 and after[args.rule] == 0 and not new_rules),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
