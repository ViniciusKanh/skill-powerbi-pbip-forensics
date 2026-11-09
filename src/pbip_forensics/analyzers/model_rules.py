"""Regras de auditoria do modelo semântico (relacionamentos e estrutura).

Distinção obrigatória de status:
- confirmed: comprovado pela estrutura dos arquivos (ex.: coluna inexistente);
- potential: risco identificado por regra, depende de intenção/dados;
- inconclusive: não foi possível avaliar com os metadados disponíveis.
"""

from __future__ import annotations

from pbip_forensics.analyzers.semantic import SemanticIndex
from pbip_forensics.models import Finding, SemanticModel

CAT_REL = "Relationships"
CAT_MODEL = "Model structure"


def _rel_ref(model: SemanticModel, rid: str) -> str:
    return f"{model.name}/relationship/{rid}"


def model_findings(model: SemanticModel, idx: SemanticIndex) -> list[Finding]:
    """Executa todas as regras MOD sobre um modelo."""
    out: list[Finding] = []
    g = idx.graph
    activated_by: dict[str, list[str]] = {}
    for ea in idx.analyses.values():
        for mod in ea.modifiers:
            if mod.function == "USERELATIONSHIP" and mod.relationship is not None:
                activated_by.setdefault(mod.relationship.id, []).append(ea.name)

    for r in model.relationships:
        ref = _rel_ref(model, r.id)
        # MOD001 — referências quebradas
        problems = []
        for tn, cn in ((r.from_table, r.from_column), (r.to_table, r.to_column)):
            tbl = model.table(tn) if tn else None
            if tbl is None:
                problems.append(f"table '{tn}' does not exist")
            elif tbl.columns and not idx.has_column(tbl.name, cn):
                problems.append(f"column '{tn}'[{cn}] does not exist")
        if problems:
            out.append(Finding(
                "MOD001", f"Relationship references missing objects: {r.id}", CAT_REL, "CRITICAL", "confirmed",
                [f"{r.label()}", *problems], r.path, ref,
                "The relationship points to a table or column that is not defined in the model files.",
                "The model may fail to load or the relationship is silently dropped, breaking filter propagation.",
                "Fix or remove the relationship so both ends reference existing columns.",
                "Open the model in Power BI Desktop and check the Model view / error list for this relationship.",
                line=r.line))
            continue
        # MOD002 — relacionamentos inativos
        if not r.is_active:
            users = sorted(set(activated_by.get(r.id, [])), key=str.lower)
            if users:
                out.append(Finding(
                    "MOD002", f"Inactive relationship activated only by DAX: {r.from_table} -> {r.to_table}",
                    CAT_REL, "INFO", "potential",
                    [r.label(), "isActive: false", f"Activated via USERELATIONSHIP in: {', '.join(users)}"],
                    r.path, ref,
                    "Inactive relationships never propagate filters unless a measure activates them.",
                    "Only the listed measures respond to filters through this path; all other measures ignore it.",
                    "Confirm this is intentional (e.g., role-playing date) and document the activating measures.",
                    "In a table visual, compare a listed measure against a non-activating measure for the same "
                    "selection.", line=r.line))
            else:
                out.append(Finding(
                    "MOD002", f"Inactive relationship not activated by any measure: {r.from_table} -> {r.to_table}",
                    CAT_REL, "LOW", "potential", [r.label(), "isActive: false",
                                                  "No USERELATIONSHIP reference found in any measure"],
                    r.path, ref,
                    "This relationship does not propagate filters and no measure in the model activates it.",
                    f"Selections on '{r.to_table}' will not filter '{r.from_table}' through this relationship; "
                    "visuals may show unrelated rows or repeated totals.",
                    "Activate it, remove it, or add measures that use USERELATIONSHIP where needed.",
                    f"Place a column of '{r.to_table}' and a column/measure of '{r.from_table}' in a table "
                    "visual and observe whether rows are restricted.", line=r.line))
        # MOD003 — bidirecional
        if r.is_bidirectional:
            roles = f"'{r.from_table}' is {g.table_role(r.from_table)}, '{r.to_table}' is {g.table_role(r.to_table)}"
            out.append(Finding(
                "MOD003", f"Bidirectional relationship: {r.from_table} <-> {r.to_table}", CAT_REL, "MEDIUM",
                "potential", [r.label(), f"crossFilteringBehavior: {r.cross_filter}", roles], r.path, ref,
                "Bidirectional cross-filtering lets the many side filter the one side, which can create "
                "additional filter paths.",
                "Possible ambiguity, unexpected filtering of dimensions and slower queries.",
                "Prefer single direction; use CROSSFILTER(..., BOTH) inside specific measures if required.",
                "Check whether slicers on related dimensions change unexpectedly when this table is filtered.",
                line=r.line))
        # MOD004 — cardinalidade
        if r.from_cardinality == "many" and r.to_cardinality == "many":
            out.append(Finding(
                "MOD004", f"Many-to-many relationship: {r.from_table} - {r.to_table}", CAT_REL, "MEDIUM",
                "potential", [r.label()], r.path, ref,
                "Many-to-many relationships rely on limited relationship semantics.",
                "Totals may not equal the sum of rows and blank-row behaviour differs from regular relationships.",
                "Confirm the grain; consider a bridge table with unique keys.",
                "Compare totals with a manual sum of detail rows for a few selections.", line=r.line))
        elif r.from_cardinality == "one" and r.to_cardinality == "one":
            out.append(Finding(
                "MOD005", f"One-to-one relationship: {r.from_table} - {r.to_table}", CAT_REL, "LOW", "potential",
                [r.label()], r.path, ref,
                "One-to-one relationships propagate filters in both directions.",
                "May indicate tables that could be merged; both tables filter each other.",
                "Validate that both columns are truly unique and whether the tables should be merged.",
                "Check uniqueness of both key columns in Power Query or with a COUNTROWS/DISTINCTCOUNT query.",
                line=r.line))
        # MOD007 — tipos diferentes nas chaves
        fc = idx.columns.get(r.from_table.lower(), {}).get(r.from_column.lower())
        tc = idx.columns.get(r.to_table.lower(), {}).get(r.to_column.lower())
        if fc and tc and fc.data_type and tc.data_type and fc.data_type != tc.data_type:
            out.append(Finding(
                "MOD007", f"Key data type mismatch: {r.from_table}[{r.from_column}] vs {r.to_table}[{r.to_column}]",
                CAT_REL, "MEDIUM", "potential", [r.label(), f"{fc.data_type} vs {tc.data_type}"], r.path, ref,
                "Relationship key columns have different declared data types.",
                "Implicit conversion can cause unmatched keys (blank member) and slower joins.",
                "Align the data types in Power Query.",
                "Look for a (Blank) member when slicing by the one-side table.", line=r.line))

    # MOD006 — ciclos e caminhos ambíguos
    for cycle in g.undirected_cycles():
        rel_ids = {r.id for r in cycle}
        tables = sorted({t for r in cycle for t in (r.from_table, r.to_table)}, key=str.lower)
        ambiguous: list[str] = []
        for src in tables:
            for dst in tables:
                if src == dst:
                    continue
                paths = [p for p in g.filter_paths(src, dst) if {h.rel.id for h in p} <= rel_ids]
                if len(paths) >= 2:
                    ambiguous.append(f"'{src}' reaches '{dst}' through {len(paths)} active paths: " + " | ".join(
                        " -> ".join([p[0].src, *[h.dst for h in p]]) for p in paths[:3]))
        ref = f"{model.name}/cycle/" + "+".join(sorted(rel_ids))
        path = cycle[0].path
        if ambiguous:
            out.append(Finding(
                "MOD006", "Ambiguous filter propagation between tables: " + ", ".join(tables), CAT_REL, "HIGH",
                "potential", [*[r.label() for r in cycle], *ambiguous[:4]], path, ref,
                "More than one active, direction-compatible path connects the same tables.",
                "Filter results depend on which path the engine uses; Power BI may also refuse to activate one "
                "of the relationships.",
                "Make one relationship inactive or single-direction so only one path remains.",
                "Open Model view in Power BI Desktop and check for ambiguity warnings; test the affected measures.",
                line=cycle[0].line))
        else:
            out.append(Finding(
                "MOD006", "Loop of active relationships (no ambiguous direction found): " + ", ".join(tables),
                CAT_REL, "INFO", "potential", [r.label() for r in cycle], path, ref,
                "The tables form a loop when direction is ignored, but cross-filter directions do not create "
                "two competing paths.",
                "Usually harmless; becomes risky if any relationship in the loop is changed to bidirectional.",
                "Document the loop; avoid adding bidirectional filters on it.",
                "Re-run this audit after any relationship change.", line=cycle[0].line))

    # MOD008 — tabelas desconectadas
    for tb in model.tables:
        if g.table_role(tb.name) != "disconnected" or tb.is_calculation_group or len(model.tables) <= 1:
            continue  # modelo de tabela única não é "desconectado"
        if tb.name.startswith("DateTableTemplate_"):
            continue
        measure_only = bool(tb.measures) and len([c for c in tb.columns if not c.is_hidden]) == 0
        if measure_only:
            continue
        users = sorted({ea.name for ea in idx.analyses.values() if any(ct == tb.name for ct, _ in ea.column_refs)},
                       key=str.lower)
        ref = f"{model.name}/table/{tb.name}"
        if users:
            out.append(Finding(
                "MOD008", f"Disconnected table used by measures: {tb.name}", CAT_MODEL, "INFO", "potential",
                [f"Table '{tb.name}' has no relationships", f"Referenced by: {', '.join(users[:8])}"], tb.path, ref,
                "A table without relationships only affects measures that read it explicitly "
                "(e.g., parameter or selection tables).",
                "Slicers on this table affect only the listed measures.",
                "Confirm the table is an intentional parameter/selection table.",
                "Change a slicer on this table and verify that only the listed measures react.", line=tb.line))
        else:
            out.append(Finding(
                "MOD008", f"Disconnected table not referenced by any measure: {tb.name}", CAT_MODEL, "LOW",
                "potential", [f"Table '{tb.name}' has no relationships",
                              "No measure references its columns"], tb.path, ref,
                "Filters on this table cannot propagate to any other table.",
                "Slicers or visuals combining this table with other tables will not filter them.",
                "Create the missing relationship or remove the table if unused.",
                "Add a slicer from this table next to a measure from a fact table and check if values change.",
                line=tb.line))

    # MOD010 — colunas-chave do lado "many" visíveis para o usuário
    visible_fk = sorted({f"'{r.from_table}'[{r.from_column}]" for r in model.relationships
                         if r.from_cardinality == "many"
                         and not r.to_table.startswith(("LocalDateTable_", "DateTableTemplate_"))
                         and (col := idx.columns.get(r.from_table.lower(), {}).get(r.from_column.lower()))
                         and not col.is_hidden})
    if visible_fk:
        out.append(Finding(
            "MOD010", f"Relationship key columns visible on the many side ({len(visible_fk)})", CAT_MODEL, "INFO",
            "potential", visible_fk[:25], model.path, f"{model.name}/visible-fk",
            "Foreign-key columns on fact tables are visible in the field list.",
            "Users may slice by the fact-side key instead of the dimension, which does not filter other facts.",
            "Hide foreign-key columns on the many side and expose the dimension columns instead.",
            "Check the Data pane: these columns should not appear to report authors."))

    # MOD009 — tabelas automáticas de data
    auto = [t.name for t in model.tables if t.name.startswith("LocalDateTable_")]
    if auto:
        out.append(Finding(
            "MOD009", f"Auto date/time tables present ({len(auto)})", CAT_MODEL, "INFO", "potential",
            [f"{len(auto)} LocalDateTable_* tables", *auto[:5]], model.path, f"{model.name}/auto-date",
            "Power BI created hidden date tables for date columns (Auto date/time option).",
            "Increases model size; time-intelligence may behave differently from a dedicated date table.",
            "Consider disabling Auto date/time and using a marked date table.",
            "Check File > Options > Current file > Data load > Auto date/time."))
    return out
