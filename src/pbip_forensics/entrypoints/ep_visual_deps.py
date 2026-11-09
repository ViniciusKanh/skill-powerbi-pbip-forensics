"""Script da skill: dependências de visuais e investigação de propagação de filtros."""

from __future__ import annotations

from typing import Any

from pbip_forensics.analyzers.filters import investigate_filter
from pbip_forensics.analyzers.semantic import build_indexes
from pbip_forensics.analyzers.stage_visual import visual_stage
from pbip_forensics.discovery.detector import discover
from pbip_forensics.entrypoints.common import skill_emit, skill_header, skill_parser, skill_run
from pbip_forensics.findings.summary import finalize
from pbip_forensics.models import ForensicsError
from pbip_forensics.security.safety import resolve_root


def visual_deps_main(argv: list[str] | None = None) -> int:
    p = skill_parser("Map Page -> Visual -> Field -> Table, validate bindings and investigate filter propagation.")
    p.add_argument("--project", required=True, help="PBIP project folder authorized for reading")
    p.add_argument("--from-table", help="table where a selection/filter is applied (investigation mode)")
    p.add_argument("--to-table", help="table expected to be filtered")
    p.add_argument("--measure", help="measure expected to react to the filter")
    p.add_argument("--visual", help="visual name or title whose filters should be included")
    a = p.parse_args(argv)
    root = resolve_root(a.project)
    project = discover(root, max_bytes=int(a.max_file_mb * 1024 * 1024))
    indexes = build_indexes(project)
    findings, dep_map, limitations = visual_stage(project, indexes)
    investigations: list[dict[str, Any]] = []
    if a.from_table:
        if not project.models:
            raise ForensicsError("No semantic model found for investigation", 2)
        visual = None
        if a.visual:
            visual = next((v for r in project.reports for v in r.visuals()
                           if a.visual.lower() in (v.name.lower(), (v.title or "").lower())), None)
            if visual is None:
                raise ForensicsError(f"Visual not found: {a.visual}", 2)
        investigations.append(investigate_filter(indexes[project.models[0].path], a.from_table, a.to_table,
                                                 a.measure, visual))
    doc = {**skill_header("visual_deps", project.root), **finalize(findings), "dependency_map": dep_map,
           "investigations": investigations, "limitations": limitations}
    skill_emit(doc, a.output, "visual_deps.json", [root])
    return 0


def main(argv: list[str] | None = None) -> int:
    return skill_run(visual_deps_main, argv)
