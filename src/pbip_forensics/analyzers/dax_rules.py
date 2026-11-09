"""Regras estáticas de DAX baseadas na árvore de chamadas (não em regex).

O uso isolado de uma função nunca é tratado como erro: as regras observam o
contexto (ex.: FILTER sobre tabela inteira *como argumento de filtro* de
CALCULATE) e produzem riscos/hipóteses, nunca valores calculados.
"""

from __future__ import annotations

from pbip_forensics.analyzers.semantic import ExprAnalysis, SemanticIndex
from pbip_forensics.models import Finding, SemanticModel
from pbip_forensics.parsers.dax import CALC_FUNCS, ITERATORS

CAT_DAX = "DAX"
CAT_PERF = "DAX performance"
CAT_CTX = "Filter context"
_TOTAL_SENSITIVE = {"HASONEVALUE", "ISINSCOPE", "HASONEFILTER", "SELECTEDVALUE", "ISFILTERED"}


def _ref(model: SemanticModel, ea: ExprAnalysis) -> str:
    return f"{model.name}/{ea.kind}/{ea.table}/{ea.name}"


def _iter_table(ea: ExprAnalysis, call_idx: int) -> str | None:
    """Tabela do primeiro argumento de um iterador, se for referência direta."""
    toks = ea.info.arg_tokens(ea.info.calls[call_idx], 0)
    if len(toks) == 1 and toks[0].kind in ("TABLE", "IDENT"):
        return toks[0].value
    return None


def dax_findings(model: SemanticModel, idx: SemanticIndex) -> list[Finding]:
    out: list[Finding] = []
    for ea in [*idx.analyses.values(), *idx.column_analyses]:
        out.extend(_expr_findings(model, idx, ea))
    for cycle in idx.measure_cycles():
        first = idx.analyses[cycle[0].lower()]
        out.append(Finding(
            "DAX002", "Circular dependency between measures: " + " -> ".join(cycle), CAT_DAX, "HIGH", "confirmed",
            [f"Measures in cycle: {', '.join(cycle)}"], first.path, f"{model.name}/cycle/" + "+".join(cycle),
            "The measures reference each other directly or indirectly.",
            "Power BI reports a circular dependency error; dependent visuals fail.",
            "Break the cycle by extracting the shared logic into a base measure.",
            "Open one of the measures in Power BI Desktop; the formula bar shows the circular dependency error.",
            line=first.line))
    return out


def _expr_findings(model: SemanticModel, idx: SemanticIndex, ea: ExprAnalysis) -> list[Finding]:
    out: list[Finding] = []
    info = ea.info
    ref = _ref(model, ea)
    owner = ea.owner
    if ea.kind == "measure" and not ea.expression.strip():
        out.append(Finding("DAX013", f"Empty measure expression: {owner}", CAT_DAX, "MEDIUM", "confirmed",
                           [f"{owner} has no expression"], ea.path, ref,
                           "The measure definition contains no DAX expression.",
                           "Visuals using it return errors or blanks.", "Provide an expression or remove it.",
                           "Inspect the measure in Power BI Desktop.", line=ea.line))
        return out
    # DAX001 — referências inexistentes
    for text, reason, status in ea.missing:
        out.append(Finding(
            "DAX001", f"Unresolved reference {text} in {owner}", CAT_DAX,
            "HIGH" if status == "confirmed" else "MEDIUM", status, [f"Expression references {text}", reason],
            ea.path, f"{ref}/{text}",
            "The referenced object is not defined in the parsed semantic model.",
            "The expression fails to evaluate; every visual using it shows an error.",
            "Fix the reference (renamed/removed object) or restore the missing object.",
            "Open the expression in Power BI Desktop; invalid references are underlined.", line=ea.line))
    if info.errors:
        out.append(Finding("DAX012", f"Tokenizer anomaly in {owner}", CAT_DAX, "MEDIUM", "potential",
                           info.errors[:5], ea.path, f"{ref}/syntax",
                           "The expression has unbalanced delimiters according to the tokenizer.",
                           "May indicate a syntax error or an unsupported construct in the parser.",
                           "Review the expression text.", "Validate the formula in Power BI Desktop.",
                           line=ea.line))
    for ci, call in enumerate(info.calls):
        line = (ea.line or 0) + info.tokens[call.index].line - 1 if ea.line else None
        parent = info.calls[call.parent] if call.parent is not None else None
        # DAX003 — FILTER sobre tabela inteira como filtro de CALCULATE
        if call.name == "FILTER" and parent and parent.name in CALC_FUNCS and (call.parent_arg or 0) >= 1:
            tbl = _iter_table(ea, ci)
            canon = idx.table_name(tbl) if tbl else None
            inner = info.calls[ci + 1] if ci + 1 < len(info.calls) and info.calls[ci + 1].parent == ci else None
            if canon:
                out.append(Finding(
                    "DAX003", f"FILTER over entire table '{canon}' used as CALCULATE filter in {owner}", CAT_PERF,
                    "MEDIUM", "potential",
                    [f"{parent.name}( ..., FILTER({canon}, ...) ) at expression line {info.tokens[call.index].line}",
                     f"'{canon}' structural role: {idx.graph.table_role(canon)}"], ea.path, f"{ref}/filter-{ci}",
                    "A table filter iterates every row of the (expanded) table and keeps all its columns as filter.",
                    "Often slower than a column predicate and may filter related tables more than intended.",
                    "Use column predicates (e.g., 'T'[Col] > x) or FILTER(VALUES('T'[Col]), ...); add KEEPFILTERS "
                    "if the intent is to intersect with existing filters.",
                    "Compare query duration (Performance Analyzer / DAX query view) before and after the change.",
                    line=line))
            elif inner and inner.name in ("ALL", "ALLSELECTED") and inner.parent_arg == 0:
                out.append(Finding(
                    "DAX003", f"FILTER({inner.name}(...)) used as CALCULATE filter in {owner}", CAT_CTX, "LOW",
                    "potential", [f"{parent.name}( ..., FILTER({inner.name}(...), ...) )"], ea.path,
                    f"{ref}/filter-{ci}",
                    "The filter argument both removes existing filters and iterates the unfiltered table.",
                    "Existing selections on that table are replaced; may also be expensive on large tables.",
                    "Confirm that overriding user selections is intended.",
                    "Apply a slicer on the table and verify whether the measure ignores it.", line=line))
        # DAX004 — iteradores aninhados / DAX005 — transição de contexto
        if call.name in ITERATORS:
            for anc, arg in ea.info.ancestors(ci):
                if info.calls[anc].name in ITERATORS and (arg or 0) >= 1 and call.name != "FILTER":
                    outer = info.calls[anc].name
                    out.append(Finding(
                        "DAX004", f"Nested iterators {outer} > {call.name} in {owner}", CAT_PERF, "MEDIUM",
                        "potential", [f"{call.name} is evaluated inside the row expression of {outer}",
                                      f"outer table: {_iter_table(ea, anc) or '(expression)'}",
                                      f"inner table: {_iter_table(ea, ci) or '(expression)'}"],
                        ea.path, f"{ref}/nested-{ci}",
                        "The inner iteration runs once per row of the outer iteration.",
                        "Cost grows with the product of both cardinalities; risk depends on data volume.",
                        "Pre-aggregate (SUMMARIZE/ADDCOLUMNS with a measure) or move logic to a column if static.",
                        "Measure server timings in DAX query view or DAX Studio with realistic filters.",
                        line=line))
                    break
            tbl = _iter_table(ea, ci)
            canon = idx.table_name(tbl) if tbl else None
            if canon and call.args and len(call.args) > 1 and call.name not in ("FILTER", "SELECTCOLUMNS"):
                s, e = call.args[1][0], call.args[-1][1]
                measure_refs = [r.name for r in info.refs_in(s, e)
                                if r.table is None and r.name.lower() in idx.measures]
                calc_inside = any(c.name in CALC_FUNCS and s <= c.index < e for c in info.calls)
                role = idx.graph.table_role(canon)
                if (measure_refs or calc_inside) and role in ("fact", "bridge", "disconnected"):
                    out.append(Finding(
                        "DAX005", f"Context transition per row of '{canon}' in {owner}", CAT_PERF, "MEDIUM",
                        "potential", [f"{call.name}({canon}, ...) evaluates "
                                      f"{', '.join('[' + m + ']' for m in measure_refs) or 'CALCULATE'} per row",
                                      f"'{canon}' structural role: {role}"], ea.path, f"{ref}/ctx-{ci}",
                        "Referencing a measure inside an iterator triggers context transition for every row.",
                        "On large fact tables this can be expensive and may duplicate rows with identical values.",
                        "Iterate a dimension or VALUES of a key column instead of the fact table.",
                        "Compare duration and results with the alternative formulation.", line=line))
    # DAX006 — modificações de contexto de filtro / DAX007 — USERELATIONSHIP/CROSSFILTER
    for mod in ea.modifiers:
        mline = (ea.line or 0) + (mod.line or 1) - 1 if ea.line else None
        if mod.function in ("USERELATIONSHIP", "CROSSFILTER"):
            if mod.relationship is None:
                out.append(Finding(
                    "DAX007", f"{mod.function} references columns without a relationship in {owner}", CAT_DAX, "HIGH",
                    "confirmed", [f"{mod.function}({', '.join(mod.targets)})",
                                  "No relationship between these columns exists in the model"],
                    ea.path, f"{ref}/{mod.function}", f"{mod.function} requires an existing relationship.",
                    "The measure returns an error.", "Reference the columns of an existing relationship.",
                    "Evaluate the measure in Power BI Desktop.", line=mline))
            elif mod.function == "USERELATIONSHIP" and mod.relationship.is_active:
                out.append(Finding(
                    "DAX007", f"USERELATIONSHIP on an already active relationship in {owner}", CAT_DAX, "INFO",
                    "potential", [mod.relationship.label()], ea.path, f"{ref}/USERELATIONSHIP",
                    "The relationship is already active, so USERELATIONSHIP has no effect.",
                    "Possibly a leftover after a model change.", "Remove it or confirm the intended relationship.",
                    "Compare results with and without the modifier.", line=mline))
            elif mod.function == "CROSSFILTER":
                out.append(Finding(
                    "DAX006", f"CROSSFILTER({mod.direction}) changes propagation in {owner}", CAT_CTX, "INFO",
                    "potential", [mod.relationship.label(), f"direction override: {mod.direction}"], ea.path,
                    f"{ref}/CROSSFILTER", "The measure overrides the relationship's cross-filter direction.",
                    "This measure reacts to filters differently from other measures.",
                    "Document the intent.", "Compare with a measure without CROSSFILTER.", line=mline))
        elif mod.function in ("ALL", "REMOVEFILTERS", "ALLEXCEPT", "ALLSELECTED") and \
                mod.context in ("calculate-filter", "filter-table"):
            out.append(Finding(
                "DAX006", f"{mod.function} modifies filter context in {owner}", CAT_CTX, "INFO", "potential",
                [f"{mod.function}({', '.join(mod.targets)}) used as {mod.context}"], ea.path,
                f"{ref}/{mod.function}-{'+'.join(mod.targets)}",
                f"{mod.function} removes (or restores) filters on {', '.join(mod.targets) or 'all tables'} for "
                "this calculation.",
                "Selections on those objects do not restrict this measure; this is a common cause of "
                "'measure ignores my slicer'.",
                "Confirm the intent; use KEEPFILTERS or narrower column targets if selections must apply.",
                "Apply a slicer on the target and compare this measure with its base measure.", line=mline))
    # DAX008 — totais potencialmente não aditivos
    if ea.kind == "measure":
        names = {c.name for c in info.calls}
        reasons = []
        branch = [c for c in info.calls if c.name in ("IF", "SWITCH")]
        has_iter = any(c.name in ITERATORS for c in info.calls)
        if branch and ea.measure_deps and not has_iter:
            reasons.append("IF/SWITCH evaluated on measure values without iterating rows: at the total level the "
                           "condition is evaluated once on the aggregate")
        sens = sorted(names & _TOTAL_SENSITIVE)
        if sens:
            reasons.append(f"uses {', '.join(sens)}: total rows follow a different branch by design")
        if "DISTINCTCOUNT" in names:
            reasons.append("DISTINCTCOUNT is non-additive: the total is not the sum of rows")
        if reasons:
            sev = "LOW" if reasons[0].startswith("IF/SWITCH") else "INFO"
            out.append(Finding(
                "DAX008", f"Total may differ from the sum of visible rows: {owner}", CAT_CTX, sev, "potential",
                reasons, ea.path, f"{ref}/totals",
                "Power BI evaluates the measure again in the total's filter context; it does not sum the rows.",
                "Users may perceive totals as wrong.",
                "If the total must be the sum of rows, iterate the grouping column (SUMX(VALUES(...), [Measure])).",
                "Export the visible rows, sum them, and compare with the total for the same filters.", line=ea.line))
        # DAX009 — divisão com '/'
        for i, tok in enumerate(info.tokens):
            if tok.kind == "OP" and tok.value == "/" and i + 1 < len(info.tokens) and \
                    info.tokens[i + 1].kind in ("BRACKET", "IDENT", "TABLE", "LPAREN"):
                out.append(Finding(
                    "DAX009", f"Division operator '/' with a non-constant denominator in {owner}", CAT_DAX, "LOW",
                    "potential", [f"'/' at expression line {tok.line}"], ea.path, f"{ref}/divide",
                    "The '/' operator raises an error/infinity when the denominator is zero or blank.",
                    "Visuals may show errors or Infinity for some selections.",
                    "Use DIVIDE(numerator, denominator) to handle zero denominators.",
                    "Select a slice where the denominator is zero or blank.", line=ea.line))
                break
        if names & {"IFERROR", "ISERROR"}:
            out.append(Finding(
                "DAX010", f"Error-handling function in {owner}", CAT_PERF, "LOW", "potential",
                [f"uses {', '.join(sorted(names & {'IFERROR', 'ISERROR'}))}"], ea.path, f"{ref}/iferror",
                "IFERROR/ISERROR can force slower evaluation and hide data problems.",
                "Possible performance cost; masked errors.", "Prefer DIVIDE or explicit checks.",
                "Compare query durations with and without the error handler.", line=ea.line))
    return out
