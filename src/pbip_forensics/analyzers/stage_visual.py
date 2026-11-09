"""Estágio de auditoria de visuais: vínculos, mapa de dependências, medidas não usadas."""

from __future__ import annotations

from typing import Any

from pbip_forensics.analyzers.dax_rules import dax_findings
from pbip_forensics.analyzers.semantic import SemanticIndex
from pbip_forensics.analyzers.visual_rules import dependency_map, visual_findings
from pbip_forensics.models import Finding, Project


def complex_measures(project: Project, indexes: dict[str, SemanticIndex]) -> set[str]:
    """Medidas com padrões DAX003/DAX004/DAX005 (usadas por VIS004)."""
    refs = [f.object_ref for m in project.models for f in dax_findings(m, indexes[m.path])
            if f.rule_id in ("DAX003", "DAX004", "DAX005")]
    return {x.name.lower() for m in project.models for x in m.all_measures()
            if any(ref.startswith(f"{m.name}/measure/{x.table}/{x.name}/") for ref in refs)}


def visual_stage(project: Project, indexes: dict[str, SemanticIndex]
                 ) -> tuple[list[Finding], list[dict[str, Any]], list[str]]:
    """Achados de visuais, mapa Página→Visual→Campo→Tabela e medidas não utilizadas."""
    complex_set = complex_measures(project, indexes)
    findings: list[Finding] = []
    limitations: list[str] = []
    dep_map: list[dict[str, Any]] = []
    for r in project.reports:
        model = project.model_for(r)
        idx = indexes.get(model.path) if model else None
        if model is None:
            limitations.append(f"Report '{r.name}': semantic model not available locally "
                               f"({r.dataset_ref or 'no datasetReference'}); field validation skipped.")
        findings.extend(visual_findings(r, model, idx, complex_set))
        dep_map.extend({"report": r.name, **row} for row in dependency_map(r, idx))
    findings.extend(_unused_measures(project, indexes, limitations))
    return findings, dep_map, limitations


def _unused_measures(project: Project, indexes: dict[str, SemanticIndex], limitations: list[str]) -> list[Finding]:
    out = []
    for m in project.models:
        idx = indexes[m.path]
        reps = [r for r in project.reports if r.model_path == m.path]
        blockers = [r.name for r in reps if r.format != "pbir" or r.support != "full" or
                    any(v.limitations for v in r.visuals())]
        if not reps or blockers:
            limitations.append(f"Unused-measure detection skipped for model '{m.name}': "
                               + ("no PBIR report bound by path" if not reps else
                                  f"reports not fully interpretable ({', '.join(blockers)})"))
            continue
        used = set()
        for r in reps:
            fields = [*r.filters, *[x for p in r.pages for x in p.filters], *[x for v in r.visuals() for x in v.fields]]
            for f in fields:
                if f.property and f.property.lower() in idx.measures:
                    used.add(f.property.lower())
        closure = set(used)
        for u in used:
            closure |= {d.lower() for d in idx.measure_closure(u)}
        for x in m.all_measures():
            if x.name.lower() not in closure:
                out.append(Finding(
                    "DAX011", f"Measure not used by any analyzed visual or measure: [{x.name}]", "DAX", "INFO",
                    "potential", [f"Not referenced by visuals/filters in: {', '.join(r.name for r in reps)}",
                                  "Not referenced by any measure that is used"], x.path,
                    f"{m.name}/measure/{x.table}/{x.name}/unused",
                    "Static analysis found no consumer for this measure in the analyzed reports.",
                    "Possibly dead code; other reports connected to the published model may still use it.",
                    "Confirm with workspace lineage / usage metrics before removing.",
                    "Search other reports connected to this model (byConnection) for the measure.",
                    line=x.line))
    return out
