"""Regras de dependência de visuais (Módulo 4) e mapa Página→Visual→Campo→Tabela."""

from __future__ import annotations

from typing import Any

from pbip_forensics.analyzers.filters import activated_relationships, reaches
from pbip_forensics.analyzers.semantic import SemanticIndex
from pbip_forensics.models import FieldRef, Finding, Report, SemanticModel
from pbip_forensics.parsers.pbir import NO_DATA_VISUALS

CAT_VIS = "Visual dependencies"
_GRID_VISUALS = {"tableEx", "pivotTable", "matrix", "table"}
VISUALS_PER_PAGE_THRESHOLD = 20  # limite orientativo de visuais com dados por página


def resolve_field(idx: SemanticIndex, report: Report, f: FieldRef) -> tuple[str, str]:
    """Classifica um campo: ('ok'|'missing-table'|'missing-field'|'kind-mismatch'|'unknown', detalhe)."""
    if f.kind in ("unknown", "visualCalculation") or not f.entity or not f.property:
        return "unknown", f.detail or "not resolvable"
    if f"{f.entity}[{f.property}]" in report.extension_measures:
        return "ok", "report-level measure (reportExtensions.json)"
    tbl = idx.model.table(f.entity)
    if tbl is None:
        return "missing-table", f"table '{f.entity}' not found in model"
    is_col = idx.has_column(tbl.name, f.property)
    is_mea = any(m.name.lower() == f.property.lower() for m in tbl.measures)
    is_hier = f.property.lower() in {h.lower() for h in tbl.hierarchies}
    if f.kind == "measure":
        if is_mea:
            return "ok", "measure"
        if f.property.lower() in idx.measures:
            return "kind-mismatch", f"measure exists but in table '{idx.measures[f.property.lower()].table}'"
        return ("kind-mismatch", "a column with this name exists") if is_col else \
            ("missing-field", f"measure '{f.property}' not found in '{tbl.name}'")
    if f.kind == "hierarchyLevel":
        return ("ok", "hierarchy") if is_hier else ("missing-field", f"hierarchy '{f.property}' not found")
    if is_col:
        return "ok", "column"
    return ("kind-mismatch", "a measure with this name exists") if is_mea else \
        ("missing-field", f"column '{f.property}' not found in '{tbl.name}'")


def unreached_bases(idx: SemanticIndex, src: str, measure: str) -> tuple[list[str], list[str]]:
    """(tabelas agregadas pela medida, tabelas que o filtro em `src` não alcança).

    Ignora tabelas de parâmetro (desconectadas) e dimensões de consulta — tabelas
    que filtram outra tabela agregada já alcançada (lidas via RELATED/LOOKUPVALUE).
    """
    bases = sorted(idx.base_tables(measure))
    reached = [b for b in bases if reaches(idx, src, b, measure)]
    blocked = [b for b in bases if b not in reached and idx.graph.table_role(b) != "disconnected"
               and not any(reaches(idx, b, r, measure) for r in reached)]
    return bases, blocked


def dependency_map(report: Report, idx: SemanticIndex | None) -> list[dict[str, Any]]:
    """Linhas Página → Visual → Campo/Medida → Tabela (com status de resolução)."""
    rows = []
    for page in report.pages:
        for v in page.visuals:
            for f in v.fields:
                status, detail = resolve_field(idx, report, f) if idx else ("unknown", "model not available")
                rows.append({"page": page.display_name, "visual": v.name, "visual_title": v.title,
                             "visual_type": v.visual_type, "usage": f.usage, "role": f.role, "kind": f.kind,
                             "table": f.entity, "field": f.property, "status": status, "detail": detail,
                             "path": v.path})
    return rows


def visual_findings(report: Report, model: SemanticModel | None, idx: SemanticIndex | None,
                    complex_measures: set[str]) -> list[Finding]:
    out: list[Finding] = []
    for page in report.pages:
        page_measures: set[str] = set()
        for v in page.visuals:
            ref = f"{report.name}/{page.name}/{v.name}"
            label = f"'{v.title or v.name}' ({v.visual_type}) on page '{page.display_name}'"
            if v.limitations and v.visual_type not in NO_DATA_VISUALS:
                out.append(Finding(
                    "VIS003", f"Visual not fully interpretable: {label}", CAT_VIS, "INFO", "inconclusive",
                    v.limitations, v.path, ref, "The visual definition uses constructs this version cannot interpret.",
                    "Dependencies of this visual may be incomplete in this audit.",
                    "Review this visual manually in Power BI Desktop.",
                    "Open the visual's field wells and filters pane."))
            if idx is None:
                continue
            measures = []
            columns = []
            for f in v.fields:
                status, detail = resolve_field(idx, report, f)
                if status in ("missing-table", "missing-field"):
                    out.append(Finding(
                        "VIS001" if status == "missing-table" else "VIS002",
                        f"Visual references missing {f.kind} {f.key()}: {label}", CAT_VIS, "HIGH", "confirmed",
                        [f"{f.usage} field {f.key()} (role '{f.role}')", detail], v.path, f"{ref}/{f.key()}",
                        "The visual binds a field that does not exist in the semantic model it is connected to.",
                        "The visual shows an error ('Something's wrong with one or more fields').",
                        "Rebind the visual to an existing field or restore the renamed/removed object.",
                        "Open the page in Power BI Desktop and check the visual for a field error."))
                elif status == "kind-mismatch":
                    out.append(Finding(
                        "VIS002", f"Field kind mismatch for {f.key()}: {label}", CAT_VIS, "MEDIUM", "potential",
                        [f"Visual declares a {f.kind}", detail], v.path, f"{ref}/{f.key()}",
                        "The visual's field type does not match the model object.",
                        "The binding may be broken after a model change.", "Rebind the field.",
                        "Check the field well in Power BI Desktop."))
                elif status == "ok" and f.usage == "projection":
                    if f.kind == "measure" and f.property and f.property.lower() in idx.measures:
                        measures.append(idx.measures[f.property.lower()].name)
                    elif f.kind in ("column", "hierarchyLevel") and f.entity:
                        columns.append(idx.table_name(f.entity) or f.entity)
            page_measures.update(measures)
            for m in measures:
                if m.lower() in complex_measures:
                    out.append(Finding(
                        "VIS004", f"Visual uses a measure flagged for performance review: [{m}]", CAT_VIS, "INFO",
                        "potential", [f"{label} uses [{m}]", f"dependency depth: {idx.depth(m)}"], v.path,
                        f"{ref}/{m}", "The measure has DAX patterns flagged by DAX003/DAX004/DAX005.",
                        "Static risk only; real impact must be measured.",
                        "Prioritize this visual when profiling with Performance Analyzer.",
                        "Record a Performance Analyzer session and check this visual's DAX query time."))
            # VIS005 — colunas cujo filtro não alcança as tabelas da medida
            for ctable in sorted(set(columns)):
                for m in measures:
                    bases, blocked = unreached_bases(idx, ctable, m)
                    if bases and blocked:
                        out.append(Finding(
                            "VIS005", f"Grouping by '{ctable}' cannot filter [{m}]: {label}", CAT_VIS, "HIGH",
                            "potential", [f"[{m}] aggregates {', '.join(sorted(bases))}",
                                          f"No active direction-compatible path from '{ctable}' to "
                                          f"{', '.join(blocked)}",
                                          "Activated relationships considered: "
                                          f"{sorted(activated_relationships(idx, m))}"],
                            v.path, f"{ref}/{ctable}->{m}",
                            "Rows grouped by this table do not restrict the measure through relationships.",
                            "Each row may repeat the same (total) value, or the visual may show combinations "
                            "the user perceives as unrelated.",
                            "Create/activate the relationship path, or use USERELATIONSHIP/TREATAS in the measure.",
                            f"Run: pbip-forensics investigate --from-table \"{ctable}\" --measure \"{m}\"."))
            # VIS006 — tabelas sem medida e sem relacionamento entre si
            tables = sorted(set(columns))
            # Uma medida/agregação "liga" as tabelas quando os filtros de ambas alcançam o que ela agrega.
            linkers: list[set[str]] = [set(idx.base_tables(m)) for m in measures]
            linkers += [{idx.table_name(f.entity) or f.entity} for f in v.fields
                        if f.usage == "projection" and f.kind == "aggregation" and f.entity]
            if v.visual_type in _GRID_VISUALS and len(tables) >= 2:
                for i, a in enumerate(tables):
                    for b in tables[i + 1:]:
                        linked = any(lk and any(reaches(idx, a, t) for t in lk) and any(reaches(idx, b, t) for t in lk)
                                     for lk in linkers)
                        if not reaches(idx, a, b) and not reaches(idx, b, a) and not linked:
                            out.append(Finding(
                                "VIS006", f"Unrelated tables combined in {label}: '{a}' and '{b}'", CAT_VIS, "HIGH",
                                "potential", [f"Columns from '{a}' and '{b}' in the same {v.visual_type}",
                                              "No active relationship path between them in either direction"],
                                v.path, f"{ref}/{a}+{b}",
                                "Power BI cannot use relationships to restrict combinations of these columns.",
                                "The visual may list rows that look unrelated (e.g., all accounts for each "
                                "customer) or show a relationship error.",
                                "Activate/create the relationship path or add a measure that defines the link.",
                                f"Run: pbip-forensics investigate --from-table \"{a}\" --to-table \"{b}\"."))
        # VIS008 — páginas com muitos visuais ligados a dados
        data_visuals = [v for v in page.visuals if any(f.usage == "projection" for f in v.fields)]
        if len(data_visuals) > VISUALS_PER_PAGE_THRESHOLD:
            out.append(Finding(
                "VIS008", f"Page '{page.display_name}' has {len(data_visuals)} data-bound visuals", CAT_VIS, "LOW",
                "potential", [f"{len(data_visuals)} visuals with data bindings (guideline: "
                              f"<= {VISUALS_PER_PAGE_THRESHOLD})", f"{len(page.visuals)} visuals in total"],
                page.path, f"{report.name}/{page.name}/visual-count",
                "Every data-bound visual sends at least one query when the page loads or a slicer changes.",
                "Slower page loads and more 'Other' time while visuals wait for each other.",
                "Consolidate KPI cards (e.g., one multi-row card), move detail to drill-through or tooltip pages.",
                "Record the page with Performance Analyzer and check 'Other' time per visual."))
        # VIS007 — filtros de página que não alcançam as medidas da página
        for pf in page.filters:
            if idx is None or not pf.entity or pf.usage != "filter" or pf.kind not in ("column", "hierarchyLevel"):
                continue
            ftable = idx.table_name(pf.entity)
            if ftable is None:
                continue
            unaffected = [m for m in sorted(page_measures, key=str.lower) if unreached_bases(idx, ftable, m)[1]]
            if unaffected:
                out.append(Finding(
                    "VIS007", f"Page filter {pf.key()} does not reach some measures on '{page.display_name}'", CAT_VIS,
                    "MEDIUM", "potential", [f"Page filter on {pf.key()}", f"Not reached: {', '.join(unaffected[:8])}"],
                    page.path, f"{report.name}/{page.name}/pagefilter/{pf.key()}",
                    "The filtered table has no active path to the tables these measures aggregate.",
                    "Those measures ignore the page filter.", "Review relationships or the filter field.",
                    "Toggle the page filter and compare measure values."))
    return out
