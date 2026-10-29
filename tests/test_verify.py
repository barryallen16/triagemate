import json
import subprocess

import pytest

from triage.verify import scan


def test_scan_counts_findings_per_rule(monkeypatch, tmp_path):
    def run(cmd, **kwargs):
        output = __import__("pathlib").Path(cmd[cmd.index("-o") + 1])
        output.write_text(json.dumps({"results": [
            {"check_id": "rule.a"}, {"check_id": "rule.a"},
            {"check_id": "rule.b"},
        ]}))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    assert scan(tmp_path / "Example.java") == {"rule.a": 2, "rule.b": 1}


def test_scan_does_not_treat_missing_output_as_clean(monkeypatch, tmp_path):
    def run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(RuntimeError, match="Semgrep failed"):
        scan(tmp_path / "Example.java")


def test_scan_raises_on_semgrep_error(monkeypatch, tmp_path):
    def run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 2, "", "scanner error")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(RuntimeError, match="scanner error"):
        scan(tmp_path / "Example.java")
