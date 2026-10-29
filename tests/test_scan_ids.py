"""A3 scan finding IDs must stay unique across files."""
import importlib.util
import json
from pathlib import Path


def load_scan_module():
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "vul4j_scan", root / "scripts" / "vul4j_scan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_java(path, class_name):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"public class {class_name} {{\n"
        f"    public void handle(String input) {{\n"
        f"        System.out.println(input);\n"
        f"    }}\n"
        f"}}\n",
        encoding="utf-8")


def test_same_rule_and_line_in_two_files_gets_distinct_ids(tmp_path):
    scan = load_scan_module()
    repo = tmp_path / "repo"
    first = repo / "a" / "Example.java"
    second = repo / "b" / "Example.java"
    make_java(first, "Example")
    make_java(second, "Example")

    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps({"results": [
        {"path": str(first), "check_id": "rule.x", "start": {"line": 3},
         "extra": {"severity": "WARNING", "message": "", "metadata": {}}},
        {"path": str(second), "check_id": "rule.x", "start": {"line": 3},
         "extra": {"severity": "WARNING", "message": "", "metadata": {}}},
    ]}), encoding="utf-8")

    entry = {"vul_id": "VUL4J-999", "cwe_id": "CWE-79"}
    rows = scan.rows_for(entry, repo, {}, scan_file)

    assert len(rows) == 2
    assert rows[0]["id"] != rows[1]["id"]
    assert rows[0]["path"] == "a/Example.java"
    assert rows[1]["path"] == "b/Example.java"
    assert rows[0]["id"].endswith(":a/Example.java:3")


def test_repo_relative_falls_back_to_basename(tmp_path):
    scan = load_scan_module()
    outside = tmp_path / "elsewhere" / "Example.java"
    make_java(outside, "Example")
    assert scan.repo_relative(outside, tmp_path / "repo") == "Example.java"


def test_test_sources_are_excluded():
    scan = load_scan_module()
    assert scan.is_test_source("src/test/java/Example.java")
    assert scan.is_test_source("core/src/testFixtures/java/Example.java")
    assert scan.is_test_source("src/it/java/Example.java")
    assert not scan.is_test_source("src/main/java/Example.java")
    assert not scan.is_test_source("Example.java")
