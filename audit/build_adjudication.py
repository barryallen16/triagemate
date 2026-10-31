"""Build the review packet for the phase 3 label adjudication sample.

Sample: all off-CWE stored TPs, all method-only stored TPs, plus 15 random
on-CWE stored TPs (seed 3407).
"""
import json
import random
import re
from pathlib import Path

WORK = Path(__file__).resolve().parent.parent
ROOT = WORK / "data"
AUDIT = WORK / "audit"


def read(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def family(cwe):
    m = re.match(r"CWE-(\d+)", cwe or "")
    return m.group(1) if m else ""


def patch_text(row, pool):
    entry = pool[row["vul_id"]]
    name = f"{entry['repo'].replace('/', '_')}_{entry['patch_commit']}.patch"
    path = AUDIT / "patches" / name
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    files = re.split(r"(?m)^diff --git ", text)
    target = None
    for block in files:
        if not block.strip():
            continue
        first = block.splitlines()[0]
        if f"b/{row['path']}" in first:
            target = "diff --git " + block
            break
    return target


def method_part(window):
    lines = window.splitlines()
    start = 0
    for i, line in enumerate(lines):
        if re.search(r"\b(class|interface|enum)\s+\w+", line):
            start = i
            break
    body = lines[start:]
    if len(body) > 90:
        body = body[:90] + ["... (truncated)"]
    return "\n".join(body)


def compact_patch(text, max_lines=70):
    out = []
    hunk = []
    header = None

    def flush():
        if not hunk:
            return
        changed = [i for i, line in enumerate(hunk)
                   if (line.startswith("+") or line.startswith("-"))
                   and not line.startswith(("+++", "---"))]
        keep = set()
        for i in changed:
            keep.update({i - 1, i, i + 1})
        out.append(header)
        for i in sorted(keep):
            if 0 <= i < len(hunk):
                out.append(hunk[i])

    for line in text.splitlines():
        if line.startswith("diff --git") or line.startswith("index "):
            continue
        if line.startswith("@@"):
            flush()
            header, hunk = line, []
        elif header is not None:
            hunk.append(line)
    flush()
    if len(out) > max_lines:
        out = out[:max_lines] + ["... (truncated)"]
    return "\n".join(out)


def main():
    rows = read(ROOT / "ghsa-eval/labels.jsonl")
    rel = {r["id"]: r for r in json.loads(
        (AUDIT / "relabel.json").read_text(encoding="utf-8"))}
    pool = {r["vul_id"]: r for r in read(ROOT / "ghsa-eval/pool.jsonl")}
    tp = [r for r in rows if r["label"] == "TP"]
    off = [r for r in tp if family(r["cwe"]) not in
           {family(c) for c in r.get("finding_cwes", [])}]
    on = [r for r in tp if r not in off]
    method = [r for r in tp if not rel[r["id"]]["hunk_tp"]]
    rng = random.Random(3407)
    on_sample = rng.sample(on, 15)
    sample = {r["id"]: r for r in off + method + on_sample}
    ordered = [r for r in tp if r["id"] in sample]
    out = ["# Label adjudication packet", "",
           f"{len(ordered)} rows: {len(off)} off-CWE, {len(method)} method-only, "
           f"15 random on-CWE. Groups overlap.", ""]
    for i, row in enumerate(ordered, 1):
        entry = pool[row["vul_id"]]
        tags = []
        if row in off:
            tags.append("off-CWE")
        if row in method:
            tags.append("method-only")
        if row in on_sample:
            tags.append("on-CWE-sample")
        if rel[row["id"]]["hunk_tp"]:
            tags.append("hunk")
        out += [f"## {i}. {row['id']}", "",
                f"- tags: {', '.join(tags)}",
                f"- advisory: {entry['summary']}",
                f"- repo: {entry['repo']}  commit: {entry['patch_commit']}",
                f"- entry CWE: {entry['cwe_ids']}  finding CWEs: {row.get('finding_cwes')}",
                f"- rule: {row['rule'].split('.')[-1]}",
                f"- finding: {row['path']}:{row['line']} method {row['method']}",
                f"- message: {row['message']}",
                "",
                "```java", method_part(row["code_window"]), "```", ""]
        patch = patch_text(row, pool)
        if patch:
            out += ["```diff", compact_patch(patch), "```", ""]
        else:
            out += ["_no patch block for this path_", ""]
    (AUDIT / "adjudication_packet.md").write_text("\n".join(out), encoding="utf-8")
    (AUDIT / "adjudication_sample.json").write_text(json.dumps(
        [{"id": r["id"], "tags": [t for t, ok in
          (("off-CWE", r in off), ("method-only", r in method),
           ("on-CWE-sample", r in on_sample)) if ok]} for r in ordered],
        indent=2), encoding="utf-8")
    print(f"wrote {len(ordered)} rows")


if __name__ == "__main__":
    main()
