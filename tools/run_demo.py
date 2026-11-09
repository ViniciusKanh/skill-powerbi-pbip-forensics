"""Gera as demonstrações reais em examples/sample_reports/ executando os scripts da
skill (como o comprador faria) e a CLI do motor sobre o projeto sintético.
Execução: python tools/run_demo.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EX = ROOT / "examples"
OUT = EX / "sample_reports"
SCRIPTS = ROOT / "agensi" / "powerbi-pbip-forensics" / "scripts"
sys.path.insert(0, str(ROOT / "src"))

from pbip_forensics.cli import main as cli_main  # noqa: E402


def run(script: str, *args: str) -> None:
    proc = subprocess.run([sys.executable, "-I", str(SCRIPTS / script), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"{script} failed: {proc.stderr}")


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    skill = OUT / "skill_outputs"
    proj, v2 = str(EX / "synthetic_project"), str(EX / "synthetic_project_v2")
    run("pbip_inspect.py", "--project", proj, "--output", str(skill))
    run("pbip_model_audit.py", "--project", proj, "--output", str(skill))
    run("pbip_visual_deps.py", "--project", proj, "--from-table", "Customer", "--to-table", "Account",
        "--visual", "Customer Accounts", "--output", str(skill))
    run("pbip_perf_log.py", "--input", str(EX / "sample_performance" / "performance.json"), "--output", str(skill))
    run("pbip_diff.py", "--before", proj, "--after", v2, "--output", str(skill))
    run("pbip_report.py", "--input", *[str(p) for p in sorted(skill.glob("*.json"))], "--output",
        str(OUT / "skill_combined_report"))
    cli_main(["audit", "--project", proj, "--performance", str(EX / "sample_performance" / "performance.json"),
              "--output", str(OUT / "cli_audit")])
    cli_main(["audit", "--project", proj, "--output", str(OUT / "cli_audit_pt-BR"), "--format", "markdown",
              "--lang", "pt-BR"])
    cli_main(["investigate", "--project", proj, "--from-table", "Customer", "--measure", "Revenue All Customers",
              "--output", str(OUT / "cli_investigation"), "--format", "all"])
    cli_main(["diff", "--before", proj, "--after", v2, "--output", str(OUT / "cli_diff"), "--format", "all"])
    print("demo outputs written to examples/sample_reports")


if __name__ == "__main__":
    main()
