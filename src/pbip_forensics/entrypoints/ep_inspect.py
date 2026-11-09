"""Script da skill: descoberta do projeto e inventário estruturado (somente leitura)."""

from __future__ import annotations

from pbip_forensics.analyzers.inventory import build_inventory
from pbip_forensics.analyzers.semantic import build_indexes
from pbip_forensics.discovery.detector import discover
from pbip_forensics.entrypoints.common import skill_emit, skill_header, skill_parser, skill_run
from pbip_forensics.findings.issues import collect_issues, issue_findings
from pbip_forensics.findings.summary import finalize
from pbip_forensics.models import to_jsonable
from pbip_forensics.security.safety import resolve_root


def inspect_main(argv: list[str] | None = None) -> int:
    p = skill_parser("Inventory a Power BI PBIP project (reports, pages, visuals, tables, measures, relationships).")
    p.add_argument("--project", required=True, help="PBIP project folder authorized for reading")
    a = p.parse_args(argv)
    root = resolve_root(a.project)
    project = discover(root, max_bytes=int(a.max_file_mb * 1024 * 1024))
    issues = collect_issues(project)
    doc = {**skill_header("inspect", project.root), "inventory": build_inventory(project, build_indexes(project)),
           "parse_issues": to_jsonable(issues), **finalize(issue_findings(issues)),
           "limitations": ["Inventory only; run the audit scripts for diagnostics."]}
    skill_emit(doc, a.output, "inspect.json", [root])
    return 0


def main(argv: list[str] | None = None) -> int:
    return skill_run(inspect_main, argv)
