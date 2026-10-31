"""Command-Line Interface for Liquid AI d1-3B Alert Triage."""
import argparse
import json
import os
import sys
from pathlib import Path
from typing import List

from d1_triage.engine import D1TriageEngine, TriageFinding
from d1_triage.formatters import print_terminal_results, save_json_report

DEMO_FINDINGS = [
    TriageFinding(
        id="DEMO-TP-01",
        rule="java.lang.security.audit.path-traversal",
        cwe="CWE-22",
        file_path="src/main/java/com/example/FileServer.java",
        line_number=45,
        message="Untrusted user input concatenated directly into File path constructor.",
        code_window="""public File getRequestedReport(String userReportName) {
    File baseDir = new File("/var/reports");
    // Dangerous sink: userReportName can contain ../../etc/passwd
    File targetFile = new File(baseDir, userReportName);
    if (!targetFile.exists()) {
        return null;
    }
    return targetFile;
}""",
        ground_truth="TP (Path Traversal without canonical path containment)",
    ),
    TriageFinding(
        id="DEMO-FP-02",
        rule="java.lang.security.audit.documentbuilderfactory",
        cwe="CWE-611",
        file_path="src/main/java/com/example/XmlHelper.java",
        line_number=28,
        message="XML parser instantiated without secure processing features.",
        code_window="""public Document parseConfig(InputStream input) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    // Guarded sink: secure processing feature is explicitly set
    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    return db.parse(input);
}""",
        ground_truth="FP (Safe: secure features explicitly neutralize XXE)",
    ),
]


def load_semgrep_json(json_path: Path) -> List[TriageFinding]:
    """Parse Semgrep standard JSON scan output into TriageFindings."""
    with open(json_path, encoding="utf-8") as fh:
        data = json.load(fh)

    results = data.get("results", [])
    findings = []
    for idx, r in enumerate(results):
        rule_id = r.get("check_id", "unknown-rule")
        cwe_list = r.get("extra", {}).get("metadata", {}).get("cwe", ["CWE-Other"])
        cwe = cwe_list[0] if isinstance(cwe_list, list) else str(cwe_list)
        path = r.get("path", "Unknown.java")
        line = r.get("start", {}).get("line", 1)
        msg = r.get("extra", {}).get("message", "")
        code_lines = r.get("extra", {}).get("lines", "")

        findings.append(TriageFinding(
            id=f"SEMGREP-{idx+1:03d}",
            rule=rule_id,
            cwe=cwe,
            file_path=path,
            line_number=line,
            code_window=code_lines,
            message=msg,
        ))
    return findings


def load_benchmark_sample(benchmark_name: str, limit: int = 5) -> List[TriageFinding]:
    """Load sample findings from the local benchmark dataset."""
    root = Path(__file__).resolve().parent.parent
    if benchmark_name.lower() == "vul4j":
        target = root / "work" / "data" / "vul4j-eval" / "scan-labeled.jsonl"
    else:
        target = root / "work" / "data" / "ghsa-eval" / "labels.jsonl"

    if not target.exists():
        sys.exit(f"Benchmark file not found: {target}")

    with open(target, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()][:limit]

    findings = []
    for r in rows:
        findings.append(TriageFinding(
            id=str(r.get("id", "finding")),
            rule=r.get("rule", "security-rule"),
            cwe=r.get("cwe", "CWE-General"),
            file_path=str(r.get("file", "Vulnerable.java")),
            line_number=r.get("line", 1),
            code_window=r.get("code_window", ""),
            message=r.get("message", ""),
            ground_truth=r.get("label", None),
        ))
    return findings


def main():
    parser = argparse.ArgumentParser(
        prog="d1-triage",
        description="Liquid AI d1-3B Static Analysis Alert Triage CLI (Runs on CPU and GPU)",
    )
    parser.add_argument("--demo", action="store_true", help="Run interactive demo on two contrasting real-world findings")
    parser.add_argument("--scan", type=Path, help="Path to Semgrep JSON scan output")
    parser.add_argument("--benchmark", type=str, choices=["ghsa", "vul4j"], help="Run triage on benchmark dataset sample")
    parser.add_argument("--limit", type=int, default=5, help="Number of benchmark alerts to evaluate (default: 5)")
    parser.add_argument("--cpu", action="store_true", help="Force CPU execution")
    parser.add_argument("--gpu", action="store_true", help="Force GPU execution (CUDA)")
    parser.add_argument("--mock", action="store_true", help="Fast integration dry-run without downloading model weights")
    parser.add_argument("--threshold", type=float, default=0.5, help="Triage probability threshold (default: 0.5)")
    parser.add_argument("--output", "-o", type=str, help="Export triage results to JSON file")
    parser.add_argument("--model", type=str, default="LiquidAI/d1-3B", help="Model name or local path")

    args = parser.parse_args()

    # Determine execution device
    device = "cpu" if args.cpu else ("cuda" if args.gpu else None)

    # Resolve findings
    if args.demo:
        findings = DEMO_FINDINGS
        print("\n[d1-triage] Running built-in demonstration (1 Real Exploitable TP vs 1 Guarded FP)...")
    elif args.scan:
        if not args.scan.exists():
            sys.exit(f"Scan file not found: {args.scan}")
        findings = load_semgrep_json(args.scan)
        print(f"\n[d1-triage] Loaded {len(findings)} findings from {args.scan}")
    elif args.benchmark:
        findings = load_benchmark_sample(args.benchmark, limit=args.limit)
        print(f"\n[d1-triage] Loaded {len(findings)} findings from {args.benchmark.upper()} benchmark")
    else:
        # Default to demo if no argument provided
        print("\nNo scan input specified. Defaulting to --demo showcase.")
        print("Use 'python -m d1_triage --help' or 'python d1_triage.py --help' to see all options.\n")
        findings = DEMO_FINDINGS

    # Initialize Engine
    engine = D1TriageEngine(
        model_name=args.model,
        device=device,
        mock=args.mock,
    )

    # Run Triage
    results = engine.triage_batch(findings, threshold=args.threshold)

    # Format & Print
    print_terminal_results(results, model_name=args.model, device=engine.device)

    # Export if requested
    if args.output:
        save_json_report(results, args.output)


if __name__ == "__main__":
    main()
