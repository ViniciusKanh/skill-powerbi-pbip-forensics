"""Testes de integração da CLI (comandos reais, códigos de saída e saídas)."""

import json
from pathlib import Path

import pytest

from pbip_forensics.cli import main
from tests.conftest import EXAMPLES, FIXTURES

PROJECT = str(EXAMPLES / "synthetic_project")


def test_scan_json(capsys):
    assert main(["scan", "--project", PROJECT]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["inventory"]["counts"]["visuals"] == 14


def test_audit_writes_all_formats(tmp_path: Path):
    out = tmp_path / "reports"
    assert main(["audit", "--project", PROJECT, "--output", str(out)]) == 0
    assert {p.name for p in out.iterdir()} == {"findings.json", "audit-report.md", "audit-report.html"}
    md = (out / "audit-report.md").read_text(encoding="utf-8")
    for section in ("Executive Summary", "Project Inventory", "Audit Scope", "Overall Findings",
                    "Severity Breakdown", "Relationship Analysis", "DAX Analysis", "Visual Dependencies",
                    "Performance Analysis", "Change Impact", "Root Cause Hypotheses", "Recommended Actions",
                    "Limitations", "Evidence Appendix"):
        assert f"## {section}" in md, section


def test_audit_fail_on(tmp_path: Path):
    assert main(["audit", "--project", PROJECT, "--output", str(tmp_path), "--fail-on", "HIGH"]) == 1
    assert main(["audit", "--project", str(FIXTURES / "simple_valid"), "--output", str(tmp_path),
                 "--fail-on", "HIGH"]) == 0


def test_audit_portuguese_headings(tmp_path: Path):
    assert main(["audit", "--project", PROJECT, "--output", str(tmp_path), "--format", "markdown",
                 "--lang", "pt-BR"]) == 0
    assert "## Resumo Executivo" in (tmp_path / "audit-report.md").read_text(encoding="utf-8")


def test_report_regenerates_from_json(tmp_path: Path, capsys):
    main(["audit", "--project", PROJECT, "--output", str(tmp_path), "--format", "json"])
    capsys.readouterr()
    assert main(["report", "--input", str(tmp_path / "findings.json"), "--format", "html"]) == 0
    assert capsys.readouterr().out.startswith("<!doctype html>")


def test_performance_command(capsys):
    assert main(["performance", "--input", str(EXAMPLES / "sample_performance" / "performance.json")]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["performance"]["visuals"][0]["visual_title"] == "Customer Accounts"


def test_diff_and_investigate(capsys):
    assert main(["diff", "--before", PROJECT, "--after", str(EXAMPLES / "synthetic_project_v2")]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["removed"] == 3
    assert main(["investigate", "--project", PROJECT, "--from-table", "Customer", "--to-table", "Account"]) == 0
    assert "Inactive relationship" in json.loads(capsys.readouterr().out)["hypotheses"][0]["hypothesis"]


@pytest.mark.parametrize("argv,code", [
    (["scan", "--project", "does/not/exist"], 2),
    (["audit", "--project", PROJECT, "--output", PROJECT + "/reports"], 4),
    (["performance", "--input", str(FIXTURES / "performance" / "malformed.json")], 5),
    (["performance", "--input", str(FIXTURES / "performance" / "wrong_shape.json")], 5),
    (["investigate", "--project", PROJECT, "--from-table", "Nope", "--to-table", "Sales"], 2),
    (["report", "--input", str(FIXTURES / "performance" / "wrong_shape.json")], 2),
])
def test_error_exit_codes(argv, code, capsys):
    assert main(argv) == code
    err = capsys.readouterr().err
    assert err.startswith("error:") and "Traceback" not in err


def test_empty_directory(tmp_path: Path, capsys):
    assert main(["scan", "--project", str(tmp_path)]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["inventory"]["counts"]["reports"] == 0


def test_file_size_limit_cli(tmp_path: Path, capsys):
    assert main(["audit", "--project", PROJECT, "--output", str(tmp_path), "--max-file-mb", "0.0005",
                 "--format", "json"]) == 0
    doc = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert any("too large" in i["message"] for i in doc["parse_issues"])


def test_audit_does_not_modify_project(tmp_path: Path):
    def snapshot(root: Path):
        return {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in root.rglob("*") if p.is_file()}
    before = snapshot(EXAMPLES / "synthetic_project")
    main(["audit", "--project", PROJECT, "--output", str(tmp_path)])
    assert snapshot(EXAMPLES / "synthetic_project") == before


def test_unicode_paths(tmp_path: Path):
    assert main(["audit", "--project", str(FIXTURES / "special_identifiers"), "--output",
                 str(tmp_path / "saída com espaço"), "--format", "markdown"]) == 0
    assert "Receita" in (tmp_path / "saída com espaço" / "audit-report.md").read_text(encoding="utf-8")
