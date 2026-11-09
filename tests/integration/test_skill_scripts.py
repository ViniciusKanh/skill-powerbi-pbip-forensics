"""Paridade e isolamento dos scripts da skill Agensi.

Cada script é copiado SOZINHO para um diretório temporário e executado com
`python -I` (modo isolado, sem site-packages do usuário e sem o diretório do
repositório no sys.path), simulando a execução da Agensi. Os resultados são
comparados com o motor modular.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from pbip_forensics.analyzers.audit import run_audit
from pbip_forensics.analyzers.diff import diff_projects
from pbip_forensics.analyzers.inventory import build_inventory
from pbip_forensics.analyzers.performance import parse_performance
from pbip_forensics.analyzers.semantic import build_indexes
from pbip_forensics.discovery.detector import discover
from tests.conftest import EXAMPLES, FIXTURES, ROOT

SCRIPTS = ROOT / "agensi" / "powerbi-pbip-forensics" / "scripts"
PROJECTS = [EXAMPLES / "synthetic_project", FIXTURES / "simple_valid", FIXTURES / "dax_patterns",
            FIXTURES / "visual_issues", FIXTURES / "special_identifiers", FIXTURES / "legacy_pbir",
            FIXTURES / "ambiguous_path", FIXTURES / "security_cases"]


def run_isolated(script: str, args: list[str], tmp: Path) -> subprocess.CompletedProcess:
    sandbox = tmp / f"sandbox_{script}"
    sandbox.mkdir(exist_ok=True)
    target = sandbox / "tmp_script.py"  # nome arbitrário, como um arquivo temporário
    shutil.copyfile(SCRIPTS / script, target)
    return subprocess.run([sys.executable, "-I", str(target), *args], capture_output=True, text=True,
                          encoding="utf-8", cwd=sandbox, timeout=120)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def key(findings: list[dict]) -> list[tuple]:
    return sorted((f["id"], f["severity"], f["status"], tuple(f["evidence"])) for f in findings)


@pytest.mark.parametrize("project", PROJECTS, ids=lambda p: p.name)
def test_audit_parity_engine_vs_scripts(project: Path, tmp_path: Path):
    out = tmp_path / "out"
    r1 = run_isolated("pbip_model_audit.py", ["--project", str(project), "--output", str(out)], tmp_path)
    r2 = run_isolated("pbip_visual_deps.py", ["--project", str(project), "--output", str(out)], tmp_path)
    assert r1.returncode == 0, r1.stderr
    assert r2.returncode == 0, r2.stderr
    script_findings = load(out / "model_audit.json")["findings"] + load(out / "visual_deps.json")["findings"]
    engine = run_audit(discover(project))
    assert key(script_findings) == key(engine["findings"])
    assert load(out / "visual_deps.json")["dependency_map"] == engine["dependency_map"]


@pytest.mark.parametrize("project", PROJECTS[:4], ids=lambda p: p.name)
def test_inspect_parity(project: Path, tmp_path: Path):
    r = run_isolated("pbip_inspect.py", ["--project", str(project)], tmp_path)
    assert r.returncode == 0, r.stderr
    p = discover(project)
    assert json.loads(r.stdout)["inventory"] == json.loads(json.dumps(build_inventory(p, build_indexes(p))))


def test_perf_parity(tmp_path: Path):
    log = EXAMPLES / "sample_performance" / "performance.json"
    r = run_isolated("pbip_perf_log.py", ["--input", str(log)], tmp_path)
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["performance"] == parse_performance(load(log))
    assert [f["severity"] for f in doc["findings"]] == ["HIGH", "MEDIUM", "MEDIUM"]


def test_diff_parity(tmp_path: Path):
    a, b = EXAMPLES / "synthetic_project", EXAMPLES / "synthetic_project_v2"
    r = run_isolated("pbip_diff.py", ["--before", str(a), "--after", str(b)], tmp_path)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["change_impact"] == json.loads(json.dumps(diff_projects(discover(a), discover(b))))


def test_report_merges_all_outputs(tmp_path: Path):
    out = tmp_path / "out"
    proj = str(EXAMPLES / "synthetic_project")
    for script, args in [("pbip_inspect.py", ["--project", proj]), ("pbip_model_audit.py", ["--project", proj]),
                         ("pbip_visual_deps.py", ["--project", proj, "--from-table", "Customer", "--to-table",
                                                  "Account"]),
                         ("pbip_perf_log.py", ["--input", str(EXAMPLES / "sample_performance" / "performance.json")]),
                         ("pbip_diff.py", ["--before", proj, "--after", str(EXAMPLES / "synthetic_project_v2")])]:
        r = run_isolated(script, [*args, "--output", str(out)], tmp_path)
        assert r.returncode == 0, (script, r.stderr)
    inputs = [str(p) for p in sorted(out.glob("*.json"))]
    r = run_isolated("pbip_report.py", ["--input", *inputs, "--output", str(tmp_path / "final")], tmp_path)
    assert r.returncode == 0, r.stderr
    md = (tmp_path / "final" / "audit-report.md").read_text(encoding="utf-8")
    assert "## Root Cause Hypotheses" in md and "Inactive relationship" in md
    assert "Customer Accounts" in md and "Change Impact" in md and "isActive: False -> True" in md
    merged = load(tmp_path / "final" / "audit-findings.json")
    perf = parse_performance(load(EXAMPLES / "sample_performance" / "performance.json"))
    engine = run_audit(discover(EXAMPLES / "synthetic_project"), perf, "performance.json")
    assert {f["id"] for f in merged["findings"]} == {f["id"] for f in engine["findings"]}


@pytest.mark.parametrize("script,args,code", [
    ("pbip_inspect.py", ["--project", "nope/nope"], 2),
    ("pbip_model_audit.py", ["--project", str(EXAMPLES / "synthetic_project"), "--output",
                             str(EXAMPLES / "synthetic_project" / "out")], 4),
    ("pbip_perf_log.py", ["--input", str(FIXTURES / "performance" / "malformed.json")], 5),
    ("pbip_visual_deps.py", ["--project", str(EXAMPLES / "synthetic_project"), "--from-table", "X",
                             "--to-table", "Sales"], 2),
])
def test_script_errors(script, args, code, tmp_path: Path):
    r = run_isolated(script, args, tmp_path)
    assert r.returncode == code
    assert r.stderr.startswith("error:") and "Traceback" not in r.stderr


def test_scripts_help_and_no_forbidden_imports(tmp_path: Path):
    for script in sorted(p.name for p in SCRIPTS.glob("*.py")):
        r = run_isolated(script, ["--help"], tmp_path)
        assert r.returncode == 0 and "usage" in r.stdout.lower(), script
        text = (SCRIPTS / script).read_text(encoding="utf-8")
        assert "pbip_forensics." not in text.split("# Módulos incluídos")[0]
        for bad in ("import subprocess", "import socket", "urllib", "os.system", "eval(", "base64"):
            assert bad not in text, (script, bad)


def test_full_audit_script_one_shot(tmp_path: Path):
    out = tmp_path / "report"
    r = run_isolated("pbip_full_audit.py", ["--project", str(EXAMPLES / "synthetic_project"), "--output", str(out)],
                     tmp_path)
    assert r.returncode == 0, r.stderr
    doc = load(out / "findings.json")
    engine = run_audit(discover(EXAMPLES / "synthetic_project"))
    assert {f["id"] for f in doc["findings"]} == {f["id"] for f in engine["findings"]}
    assert (out / "audit-report.html").read_text(encoding="utf-8").startswith("<!doctype html>")
