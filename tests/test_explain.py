from triage.explain import FIX_HINTS, GENERIC_FIX, explain

ROW = {
    "rule": "java.lang.security.audit.path-traversal",
    "cwe": "CWE-22",
    "file": "src/main/java/App.java",
    "line": 42,
    "message": "Path is built from user input.",
}


def test_tp_uses_cwe_fix_hint():
    got = explain(ROW, "TP")
    assert got == {"why": ROW["message"], "fix": FIX_HINTS["CWE-22"]}


def test_unknown_cwe_uses_generic_fix_hint():
    assert explain({**ROW, "cwe": "CWE-999"}, "TP")["fix"] == GENERIC_FIX


def test_fp_has_no_fix():
    assert explain(ROW, "FP")["fix"] == ""


def test_missing_message_includes_rule_and_location():
    got = explain({**ROW, "message": ""}, "TP")
    assert "path-traversal" in got["why"]
    assert "App.java:42" in got["why"]
