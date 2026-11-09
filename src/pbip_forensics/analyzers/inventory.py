"""Inventário estruturado do projeto (nomes, identificadores e caminhos de origem)."""

from __future__ import annotations

from typing import Any

from pbip_forensics.analyzers.semantic import SemanticIndex
from pbip_forensics.models import Project


def build_inventory(project: Project, indexes: dict[str, SemanticIndex]) -> dict[str, Any]:
    """Inventário estruturado com nomes, identificadores e caminhos de origem."""
    models = []
    for m in project.models:
        idx = indexes.get(m.path)
        tables = []
        for t in m.tables:
            tables.append({
                "name": t.name, "path": t.path, "line": t.line, "role": idx.graph.table_role(t.name) if idx else None,
                "is_hidden": t.is_hidden, "is_calculated": t.is_calculated,
                "is_calculation_group": t.is_calculation_group, "columns": [c.name for c in t.columns],
                "calculated_columns": [c.name for c in t.columns if c.is_calculated],
                "measures": [x.name for x in t.measures], "hierarchies": t.hierarchies,
                "partition_kinds": t.partition_kinds, "data_sources": t.data_sources})
        measures = []
        for x in m.all_measures():
            ea = idx.analyses.get(x.name.lower()) if idx else None
            measures.append({"table": x.table, "name": x.name, "path": x.path, "line": x.line,
                             "display_folder": x.display_folder, "is_hidden": x.is_hidden,
                             "measure_dependencies": ea.measure_deps if ea else [],
                             "column_references": [f"'{a}'[{b}]" for a, b in ea.column_refs] if ea else [],
                             "depth": idx.depth(x.name) if idx else None})
        models.append({
            "name": m.name, "path": m.path, "format": m.format, "support": m.support,
            "pbism_version": m.pbism_version, "tables": tables, "measures": measures,
            "relationships": [{"id": r.id, "from": f"'{r.from_table}'[{r.from_column}]",
                               "to": f"'{r.to_table}'[{r.to_column}]", "is_active": r.is_active,
                               "cross_filter": r.cross_filter,
                               "cardinality": f"{r.from_cardinality}:{r.to_cardinality}",
                               "path": r.path, "line": r.line} for r in m.relationships],
            "roles": m.roles, "shared_expressions": m.shared_expressions,
            "components": idx.graph.components() if idx else []})
    reports = []
    for r in project.reports:
        reports.append({
            "name": r.name, "path": r.path, "format": r.format, "support": r.support,
            "pbir_version": r.pbir_version, "dataset_reference": r.dataset_ref, "model_path": r.model_path,
            "report_filters": [f.key() for f in r.filters], "extension_measures": r.extension_measures,
            "pages": [{"name": p.name, "display_name": p.display_name, "path": p.path,
                       "page_filters": [f.key() for f in p.filters],
                       "visuals": [{"name": v.name, "title": v.title, "type": v.visual_type, "path": v.path,
                                    "is_custom": v.is_custom, "field_count": len(v.fields),
                                    "visual_filters": v.filter_count, "limitations": v.limitations}
                                   for v in p.visuals]} for p in r.pages]})
    counts = {
        "pbip_files": len(project.pbip_files), "reports": len(project.reports),
        "pages": sum(len(r.pages) for r in project.reports),
        "visuals": sum(len(r.visuals()) for r in project.reports),
        "semantic_models": len(project.models), "tables": sum(len(m.tables) for m in project.models),
        "columns": sum(len(t.columns) for m in project.models for t in m.tables),
        "measures": sum(len(m.all_measures()) for m in project.models),
        "relationships": sum(len(m.relationships) for m in project.models),
    }
    return {"counts": counts, "pbip_files": project.pbip_files, "models": models, "reports": reports,
            "skipped_items": project.skipped}
