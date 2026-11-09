"""Script da skill: comparação entre duas versões de um projeto PBIP."""

from __future__ import annotations

from pbip_forensics.analyzers.diff import diff_projects
from pbip_forensics.discovery.detector import discover
from pbip_forensics.entrypoints.common import skill_emit, skill_header, skill_parser, skill_run
from pbip_forensics.security.safety import resolve_root


def diff_main(argv: list[str] | None = None) -> int:
    p = skill_parser("Compare two PBIP project versions and estimate change impact.")
    p.add_argument("--before", required=True, help="previous version folder")
    p.add_argument("--after", required=True, help="current version folder")
    a = p.parse_args(argv)
    r1, r2 = resolve_root(a.before), resolve_root(a.after)
    limit = int(a.max_file_mb * 1024 * 1024)
    before, after = discover(r1, max_bytes=limit), discover(r2, max_bytes=limit)
    impact = diff_projects(before, after)
    doc = {**skill_header("diff", f"{before.root} -> {after.root}"), "change_impact": impact, "findings": [],
           "limitations": [impact["note"]]}
    skill_emit(doc, a.output, "diff.json", [r1, r2])
    return 0


def main(argv: list[str] | None = None) -> int:
    return skill_run(diff_main, argv)
