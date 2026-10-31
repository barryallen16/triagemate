"""Comprehensive End-to-End Test Suite for Liquid AI d1-3B Benchmark & Triage Toolkit."""
import json
import subprocess
import sys
from pathlib import Path

# Paths
ROOT = Path(__file__).resolve().parent.parent.parent
AUDIT = ROOT / "work" / "audit"
DATA = ROOT / "work" / "data"

passed_tests = 0
failed_tests = 0


def log_test(name: str, status: bool, details: str = ""):
    global passed_tests, failed_tests
    tag = "[PASS]" if status else "[FAIL]"
    print(f"  {tag:<7} {name}")
    if details:
        print(f"          {details}")
    if status:
        passed_tests += 1
    else:
        failed_tests += 1


def test_1_benchmark_data_integrity():
    print("\n--- Test Suite 1: Dataset Integrity & Leakage Safeguards ---")
    # 1. GHSA labels
    ghsa_path = DATA / "ghsa-eval" / "labels.jsonl"
    ghsa_rows = [json.loads(l) for l in open(ghsa_path, encoding="utf-8") if l.strip()]
    log_test("GHSA Evaluation Set Exists & Has Exactly 174 Rows", len(ghsa_rows) == 174, f"Found {len(ghsa_rows)} rows")

    # 2. Vul4J labels
    vul4j_path = DATA / "vul4j-eval" / "scan-labeled.jsonl"
    vul4j_rows = [json.loads(l) for l in open(vul4j_path, encoding="utf-8") if l.strip()]
    log_test("Vul4J Evaluation Set Exists & Has Exactly 14 Rows", len(vul4j_rows) == 14, f"Found {len(vul4j_rows)} rows")

    # 3. Relabel map
    relabel_path = AUDIT / "relabel.json"
    relabel = json.loads(open(relabel_path, encoding="utf-8").read())
    log_test("Audit Relabel Mapping Exists & Covers 174 IDs", len(relabel) == 174, f"Mapped {len(relabel)} items")

    # 4. Contrastive Training Set
    train_path = AUDIT / "contrastive_train.jsonl"
    train_rows = [json.loads(l) for l in open(train_path, encoding="utf-8") if l.strip()]
    tps = sum(1 for r in train_rows if r["label"] == "TP")
    fps = sum(1 for r in train_rows if r["label"] == "FP")
    log_test("Contrastive Training Set Has Exactly 416 Balanced Rows", len(train_rows) == 416 and tps == 208 and fps == 208,
             f"Total: {len(train_rows)} | TP: {tps} | FP: {fps}")

    # 5. Data Leakage Verification: Zero overlap between training and eval sets
    eval_vuls = {r["vul_id"] for r in ghsa_rows}
    train_vuls = {r.get("vul_id", r.get("id")) for r in train_rows}
    overlap = eval_vuls.intersection(train_vuls)
    log_test("Zero-Leakage Guarantee: Training Set Has 0 Overlap with Evaluation Set", len(overlap) == 0,
             f"Overlap count: {len(overlap)}")


def test_2_prediction_artifacts():
    print("\n--- Test Suite 2: Model Prediction Artifacts Completeness ---")
    files_to_check = [
        ("d1_targeted_identity_ghsa.jsonl", 174),
        ("d1_targeted_swap_ghsa.jsonl", 174),
        ("d1_lora_identity_ghsa.jsonl", 174),
        ("d1_lora_swap_ghsa.jsonl", 174),
        ("d1_lora_identity_vul4j.jsonl", 14),
    ]
    for filename, expected_len in files_to_check:
        p = AUDIT / filename
        if not p.exists():
            log_test(f"File {filename} exists", False, "File missing")
            continue
        rows = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
        valid_scores = all("p_tp" in r and 0.0 <= float(r["p_tp"]) <= 1.0 for r in rows)
        log_test(f"{filename} ({expected_len} rows, valid probabilities [0, 1])",
                 len(rows) == expected_len and valid_scores,
                 f"Rows: {len(rows)}, Valid probs: {valid_scores}")


def test_3_evaluation_harnesses():
    print("\n--- Test Suite 3: Standalone Evaluation Harnesses ---")
    # Run evaluate_d1.py
    proc = subprocess.run([sys.executable, str(AUDIT / "evaluate_d1.py")], capture_output=True, text=True)
    out = proc.stdout
    success = (proc.returncode == 0) and ("L3 (Clean hunk + CWE)" in out) and ("Vul4J Benchmark Evaluation" in out)
    log_test("evaluate_d1.py executes cleanly (Exit Code 0)", success, f"Output length: {len(out)} chars")

    # Run compare_all_phases.py
    proc2 = subprocess.run([sys.executable, str(AUDIT / "compare_all_phases.py")], capture_output=True, text=True)
    out2 = proc2.stdout
    success2 = (proc2.returncode == 0) and ("Heuristic Baseline" in out2) and ("Phase 3 (Contrastive LoRA)" in out2)
    log_test("compare_all_phases.py executes cleanly (Exit Code 0)", success2, f"Output length: {len(out2)} chars")


def test_4_sink_finder():
    print("\n--- Test Suite 4: Statement-Level Sink Finder Logic ---")
    sys.path.insert(0, str(ROOT))
    from d1_triage.sink_finder import build_annotated_prompt, find_sink_line

    # Test Path Traversal
    code_pt = """public void read(String path) {
    File f = new File(baseDir, path);
    FileInputStream fis = new FileInputStream(f);
}"""
    idx, stmt = find_sink_line(code_pt, "java.lang.security.audit.path-traversal")
    log_test("Sink Finder catches 'new File' in Path Traversal", "new File" in stmt, f"Matched statement: '{stmt}'")

    # Test XML Secure Processing
    code_xml = """public void parse(InputStream is) {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
}"""
    idx_xml, stmt_xml = find_sink_line(code_xml, "documentbuilderfactory")
    log_test("Sink Finder catches 'DocumentBuilderFactory' in XXE", "DocumentBuilderFactory" in stmt_xml, f"Matched statement: '{stmt_xml}'")

    # Test Annotated Prompt Formatting
    prompt = build_annotated_prompt(code_pt, "path-traversal", "CWE-22", 15)
    log_test("Annotated Prompt contains '>>> [ALERT LINE 15]'", ">>> [ALERT LINE 15]:" in prompt, "Sink line properly marked")


def test_5_d1_triage_cli():
    print("\n--- Test Suite 5: d1-triage CLI Functionality ---")
    # 1. Demo mock
    p1 = subprocess.run([sys.executable, "d1_triage.py", "--demo", "--mock"], capture_output=True, text=True, cwd=str(ROOT))
    log_test("d1_triage --demo --mock runs with Rich formatting", p1.returncode == 0 and "Triage Summary" in p1.stdout,
             f"Output lines: {len(p1.stdout.splitlines())}")

    # 2. Benchmark sampling GHSA
    p2 = subprocess.run([sys.executable, "d1_triage.py", "--benchmark", "ghsa", "--limit", "3", "--mock"], capture_output=True, text=True, cwd=str(ROOT))
    log_test("d1_triage --benchmark ghsa --limit 3 --mock", p2.returncode == 0 and "Total Alerts Analyzed: 3" in p2.stdout)

    # 3. Benchmark sampling Vul4J
    p3 = subprocess.run([sys.executable, "d1_triage.py", "--benchmark", "vul4j", "--limit", "2", "--mock"], capture_output=True, text=True, cwd=str(ROOT))
    log_test("d1_triage --benchmark vul4j --limit 2 --mock", p3.returncode == 0 and "Total Alerts Analyzed: 2" in p3.stdout)

    # 4. JSON Export
    test_json_out = ROOT / "test_out.json"
    if test_json_out.exists():
        test_json_out.unlink()
    p4 = subprocess.run([sys.executable, "d1_triage.py", "--demo", "--mock", "-o", str(test_json_out)], capture_output=True, text=True, cwd=str(ROOT))
    exists_and_valid = False
    if test_json_out.exists():
        try:
            d = json.loads(test_json_out.read_text(encoding="utf-8"))
            exists_and_valid = (len(d) == 2 and "is_exploitable" in d[0])
            test_json_out.unlink()
        except Exception:
            pass
    log_test("d1_triage JSON Export (--output)", exists_and_valid, "Valid JSON structure verified")


def main():
    print("=" * 75)
    print("      LIQUID AI d1-3B BENCHMARK & TOOLKIT: END-TO-END VERIFICATION")
    print("=" * 75)

    test_1_benchmark_data_integrity()
    test_2_prediction_artifacts()
    test_3_evaluation_harnesses()
    test_4_sink_finder()
    test_5_d1_triage_cli()

    print("\n" + "=" * 75)
    print(f"  TEST RESULTS SUMMARY: {passed_tests} PASSED / {failed_tests} FAILED")
    print("=" * 75)

    if failed_tests > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
