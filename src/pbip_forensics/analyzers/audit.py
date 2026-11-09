"""Orquestração da auditoria completa (comando `audit`)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pbip_forensics.analyzers.inventory import build_inventory
from pbip_forensics.analyzers.performance import performance_findings
from pbip_forensics.analyzers.semantic import build_indexes
from pbip_forensics.analyzers.stage_model import BASE_LIMITATIONS, model_stage
from pbip_forensics.analyzers.stage_visual import visual_stage
from pbip_forensics.findings.issues import collect_issues
from pbip_forensics.findings.summary import finalize
from pbip_forensics.models import TOOL_NAME, TOOL_VERSION, Finding, Project, to_jsonable


def run_audit(project: Project, perf: dict[str, Any] | None = None, perf_source: str = "",
              thresholds: dict[str, float] | None = None) -> dict[str, Any]:
    """Executa todos os módulos estáticos e consolida o resultado."""
    t0 = datetime.now(UTC)
    indexes = build_indexes(project)
    findings: list[Finding]
    findings, limitations = model_stage(project, indexes)
    limitations = [*BASE_LIMITATIONS, *limitations]
    vis, dep_map, vis_lim = visual_stage(project, indexes)
    findings.extend(vis)
    limitations.extend(vis_lim)
    if perf is not None:
        names = {v.name: f"{r.name}/{p.display_name}/{v.title or v.name}" for r in project.reports
                 for p in r.pages for v in p.visuals}
        findings.extend(performance_findings(perf, perf_source, thresholds, names))
    else:
        limitations.append("No Performance Analyzer log provided: performance section lists static risks only; "
                           "no runtime measurements are available.")
    final = finalize(findings)
    elapsed = (datetime.now(UTC) - t0).total_seconds() * 1000
    return {
        "tool": TOOL_NAME, "version": TOOL_VERSION, "generated_at": t0.isoformat(timespec="seconds"),
        "project": project.root,
        "scope": {"project": project.root, "read_only": True, "performance_log": perf_source or None,
                  "modules": ["discovery", "semantic-model", "dax", "visual-dependencies", "filters"]
                  + (["performance"] if perf else [])},
        "inventory": build_inventory(project, indexes),
        "severity_breakdown": final["severity_breakdown"],
        "status_breakdown": final["status_breakdown"],
        "findings": final["findings"],
        "dependency_map": dep_map,
        "performance": perf,
        "change_impact": None,
        "investigations": [],
        "parse_issues": to_jsonable(collect_issues(project)),
        "limitations": limitations,
        "metrics": {"analysis_ms": round(elapsed, 1), "findings_total": len(final["findings"])},
    }
