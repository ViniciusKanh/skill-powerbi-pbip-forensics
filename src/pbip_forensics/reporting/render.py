"""Geração de relatórios Markdown, HTML estático e JSON a partir do documento
de auditoria. O conteúdo é montado uma única vez como "blocos" e depois
renderizado em cada formato, garantindo que MD e HTML tenham as mesmas seções.

Idiomas: inglês (padrão) e português do Brasil (títulos e rótulos). Os textos
dos achados permanecem em inglês nesta versão.
"""

from __future__ import annotations

import html
import json
from typing import Any

Block = tuple[Any, ...]

LABELS = {
    "en": {
        "title": "Power BI PBIP Forensics — Audit Report", "exec": "Executive Summary",
        "inventory": "Project Inventory", "scope": "Audit Scope", "overall": "Overall Findings",
        "severity": "Severity Breakdown", "relationships": "Relationship Analysis", "dax": "DAX Analysis",
        "visuals": "Visual Dependencies", "performance": "Performance Analysis", "impact": "Change Impact",
        "hypotheses": "Root Cause Hypotheses", "actions": "Recommended Actions", "limitations": "Limitations",
        "appendix": "Evidence Appendix", "none": "No findings in this section.",
        "no_perf": "No Performance Analyzer log was provided. No runtime measurements are available; the items "
                   "below are static risks that should be measured before acting.",
        "no_impact": "No version comparison was requested for this report.",
        "no_hyp": "No investigation was requested. Use the `investigate` command for question-driven analysis.",
    },
    "pt-BR": {
        "title": "Power BI PBIP Forensics — Relatório de Auditoria", "exec": "Resumo Executivo",
        "inventory": "Inventário do Projeto", "scope": "Escopo da Auditoria", "overall": "Achados Gerais",
        "severity": "Distribuição por Severidade", "relationships": "Análise de Relacionamentos",
        "dax": "Análise DAX", "visuals": "Dependências de Visuais", "performance": "Análise de Desempenho",
        "impact": "Impacto de Alterações", "hypotheses": "Hipóteses de Causa Raiz",
        "actions": "Ações Recomendadas", "limitations": "Limitações", "appendix": "Apêndice de Evidências",
        "none": "Nenhum achado nesta seção.",
        "no_perf": "Nenhum log do Performance Analyzer foi informado. Não há medições reais; os itens abaixo são "
                   "riscos estáticos que devem ser medidos antes de qualquer ação.",
        "no_impact": "Nenhuma comparação de versões foi solicitada.",
        "no_hyp": "Nenhuma investigação foi solicitada. Use o comando `investigate`.",
    },
}

_REL_CATS = {"Relationships", "Model structure"}
_DAX_CATS = {"DAX", "DAX performance", "Filter context"}


def _ftable(findings: list[dict[str, Any]]) -> Block:
    return ("table", ["ID", "Severity", "Status", "Category", "Title"],
            [[f["id"], f["severity"], f["status"], f["category"], f["title"]] for f in findings])


def build_blocks(doc: dict[str, Any], lang: str = "en", max_rows: int = 200) -> list[Block]:
    """Monta a estrutura de seções exigida para o relatório."""
    L = LABELS.get(lang, LABELS["en"])
    findings: list[dict[str, Any]] = doc.get("findings", [])
    inv = doc.get("inventory", {})
    counts = inv.get("counts", {})
    sev = doc.get("severity_breakdown", {})
    st = doc.get("status_breakdown", {})
    b: list[Block] = [("h1", L["title"]),
                      ("p", f"Project: **{doc.get('project')}** · Tool {doc.get('tool')} {doc.get('version')} · "
                            f"Generated (UTC): {doc.get('generated_at')}")]
    # 1. Resumo executivo
    b.append(("h2", L["exec"]))
    top = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    if sev:
        b.append(("p", f"{len(findings)} findings: " + ", ".join(f"{k} {v}" for k, v in sev.items()) +
                  f". Confirmed {st.get('confirmed', 0)}, potential {st.get('potential', 0)}, "
                  f"inconclusive {st.get('inconclusive', 0)}."))
    else:
        b.append(("p", f"{len(findings)} findings produced by this command (full rule set runs with `audit`)."))
    b.append(("p", f"Inventory: {counts.get('reports', 0)} report(s), {counts.get('pages', 0)} page(s), "
                   f"{counts.get('visuals', 0)} visual(s), {counts.get('semantic_models', 0)} model(s), "
                   f"{counts.get('tables', 0)} table(s), {counts.get('measures', 0)} measure(s), "
                   f"{counts.get('relationships', 0)} relationship(s)."))
    if top:
        b.append(("ul", [f"**{f['severity']}/{f['status']}** {f['title']} (`{f['id']}`)" for f in top[:10]]))
    # 2. Inventário
    b.append(("h2", L["inventory"]))
    b.append(("table", ["Item", "Count"], [[k, str(v)] for k, v in counts.items()]))
    for r in inv.get("reports", []):
        b.append(("h3", f"Report: {r['name']} ({r['format']}, support: {r['support']})"))
        b.append(("p", f"Path `{r['path']}` · PBIR version {r.get('pbir_version')} · dataset reference: "
                       f"{r.get('dataset_reference')}"))
        rows = [[p["display_name"], v["title"] or v["name"], v["type"], str(v["field_count"]), str(v["visual_filters"]),
                 "; ".join(v["limitations"])] for p in r["pages"] for v in p["visuals"]]
        b.append(("table", ["Page", "Visual", "Type", "Fields", "Visual filters", "Limitations"], rows[:max_rows]))
    for m in inv.get("models", []):
        b.append(("h3", f"Semantic model: {m['name']} ({m['format']}, support: {m['support']})"))
        b.append(("table", ["Table", "Role", "Columns", "Measures", "Calculated", "Data sources"],
                  [[t["name"], str(t["role"]), str(len(t["columns"])), str(len(t["measures"])),
                    "yes" if t["is_calculated"] else "", ", ".join(t["data_sources"])] for t in m["tables"]]))
    # 3. Escopo
    b.append(("h2", L["scope"]))
    sc = doc.get("scope", {})
    b.append(("ul", [f"Project folder: `{sc.get('project')}` (read-only: {sc.get('read_only')})",
                     f"Modules: {', '.join(sc.get('modules', []))}",
                     f"Performance log: {sc.get('performance_log') or 'not provided'}",
                     f"Skipped items (security/scope): {len(inv.get('skipped_items', []))}"]))
    # 4/5. Achados e severidade
    b.append(("h2", L["overall"]))
    b.append(_ftable(findings) if findings else ("p", L["none"]))
    b.append(("h2", L["severity"]))
    b.append(("table", ["Severity", "Count"], [[k, str(v)] for k, v in sev.items()]))
    b.append(("table", ["Status", "Count"], [[k, str(v)] for k, v in st.items()]))
    # 6. Relacionamentos
    b.append(("h2", L["relationships"]))
    for m in inv.get("models", []):
        b.append(("table", ["From", "To", "Active", "Cross filter", "Cardinality"],
                  [[r["from"], r["to"], str(r["is_active"]), r["cross_filter"], r["cardinality"]]
                   for r in m["relationships"]]))
    rel = [f for f in findings if f["category"] in _REL_CATS]
    b.append(_ftable(rel) if rel else ("p", L["none"]))
    # 7. DAX
    b.append(("h2", L["dax"]))
    dax = [f for f in findings if f["category"] in _DAX_CATS]
    b.append(_ftable(dax) if dax else ("p", L["none"]))
    for m in inv.get("models", []):
        deep = sorted(m["measures"], key=lambda x: -(x.get("depth") or 0))[:15]
        b.append(("table", ["Measure", "Depth", "Depends on"],
                  [[f"[{x['name']}]", str(x.get("depth")), ", ".join(x["measure_dependencies"])] for x in deep]))
    # 8. Visuais
    b.append(("h2", L["visuals"]))
    vis = [f for f in findings if f["category"] == "Visual dependencies"]
    b.append(_ftable(vis) if vis else ("p", L["none"]))
    dm = doc.get("dependency_map", [])
    b.append(("p", f"Dependency map: {len(dm)} bindings (Page → Visual → Field → Table)"
                   + (f"; first {max_rows} shown, full list in JSON." if len(dm) > max_rows else ".")))
    b.append(("table", ["Page", "Visual", "Usage", "Kind", "Table", "Field", "Status"],
              [[d["page"], d["visual_title"] or d["visual"], d["usage"], d["kind"], str(d["table"]), str(d["field"]),
                d["status"]] for d in dm[:max_rows]]))
    # 9. Desempenho
    b.append(("h2", L["performance"]))
    perf = doc.get("performance")
    if perf:
        b.append(("p", f"Log version {perf.get('version')}, {perf.get('event_count')} events, "
                       f"{len(perf.get('visuals', []))} visual lifecycles (sorted by measured total)."))
        b.append(("table", ["Visual", "Type", "Total ms", "DAX ms", "DirectQuery ms", "Display ms", "Other ms"],
                  [[str(v["visual_title"] or v["visual_id"]), str(v["visual_type"]), _n(v["total_ms"]),
                    _n(v["dax_query_ms"]), _n(v["direct_query_ms"]), _n(v["visual_display_ms"]), _n(v["other_ms"])]
                   for v in perf.get("visuals", [])[:max_rows]]))
        if perf.get("warnings"):
            b.append(("ul", perf["warnings"]))
        pf = [f for f in findings if f["category"] == "Performance"]
        b.append(_ftable(pf) if pf else ("p", L["none"]))
    else:
        b.append(("p", L["no_perf"]))
        risks = [f for f in findings if f["category"] == "DAX performance"]
        b.append(_ftable(risks) if risks else ("p", L["none"]))
    # 10. Impacto
    b.append(("h2", L["impact"]))
    ci = doc.get("change_impact")
    if ci:
        b.append(("p", "Summary: " + ", ".join(f"{k} {v}" for k, v in ci["summary"].items()) + ". " + ci["note"]))
        b.append(("table", ["Type", "Object", "Change", "Details"],
                  [[c["object_type"], c["object"], c["change"], "; ".join(c["details"])] for c in ci["changes"]]))
        for imp in ci["impacts"]:
            b.append(("h3", imp["change"]))
            b.append(("p", imp["message"]))
            b.append(("ul", [f"Dependent measure: {x}" for x in imp["dependent_measures"]]
                      + [f"Visual: {x}" for x in imp["affected_visuals"]] or ["No dependents found."]))
    else:
        b.append(("p", L["no_impact"]))
    # 11. Hipóteses
    b.append(("h2", L["hypotheses"]))
    invs = doc.get("investigations", [])
    if invs:
        for inv_ in invs:
            b.append(("h3", f"Investigation: {inv_.get('from_table')} → {', '.join(inv_.get('targets', []))}"
                            + (f" (measure {inv_['measure']})" if inv_.get("measure") else "")))
            b.append(("p", "Deterministic evidence:"))
            b.append(("pre", "\n".join(inv_.get("evidence", []))))
            for h in inv_.get("hypotheses", []):
                b.append(("p", f"**#{h['rank']} [{h['confidence']} confidence]** {h['hypothesis']} — "
                               f"{h['justification']}"))
                b.append(("ul", h["verification_steps"]))
    else:
        b.append(("p", L["no_hyp"]))
    # 12. Ações
    b.append(("h2", L["actions"]))
    seen, actions = set(), []
    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM") and (f["rule_id"], f["recommendation"]) not in seen:
            seen.add((f["rule_id"], f["recommendation"]))
            actions.append(f"[{f['severity']}] {f['rule_id']}: {f['recommendation']}")
    b.append(("ol", actions) if actions else ("p", L["none"]))
    # 13. Limitações
    b.append(("h2", L["limitations"]))
    b.append(("ul", doc.get("limitations", [])))
    # 14. Apêndice
    b.append(("h2", L["appendix"]))
    for f in findings:
        loc = f["path"] + (f":{f['line']}" if f.get("line") else "")
        b.append(("h3", f"{f['id']} — {f['title']}"))
        b.append(("ul", [f"Severity: {f['severity']} · Status: {f['status']} · Category: {f['category']}",
                         f"Source: `{loc}` · Object: `{f['object_ref']}`",
                         f"Explanation: {f['explanation']}", f"Impact: {f['impact']}",
                         f"Recommendation: {f['recommendation']}", f"Verification: {f['verification']}"]))
        b.append(("pre", "\n".join(f["evidence"])))
    return b


def _n(v: Any) -> str:
    return "" if v is None else f"{float(v):.1f}"


def _md_cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(blocks: list[Block]) -> str:
    out: list[str] = []
    for blk in blocks:
        kind = blk[0]
        if kind in ("h1", "h2", "h3"):
            out += [f"{'#' * int(kind[1])} {blk[1]}", ""]
        elif kind == "p":
            out += [blk[1], ""]
        elif kind in ("ul", "ol"):
            out += [f"{i + 1}. {x}" if kind == "ol" else f"- {x}" for i, x in enumerate(blk[1])] + [""]
        elif kind == "pre":
            out += ["```text", blk[1], "```", ""]
        elif kind == "table":
            headers, rows = blk[1], blk[2]
            if not rows:
                out += ["_(empty)_", ""]
                continue
            out.append("| " + " | ".join(headers) + " |")
            out.append("|" + "---|" * len(headers))
            out += ["| " + " | ".join(_md_cell(c) for c in r) + " |" for r in rows] + [""]
    return "\n".join(out).rstrip() + "\n"


def _inline(text: str) -> str:
    """Escapa HTML e converte **negrito** e `código` (sem executar nada)."""
    esc = html.escape(text)
    parts = esc.split("**")
    esc = "".join(f"<strong>{p}</strong>" if i % 2 else p for i, p in enumerate(parts))
    parts = esc.split("`")
    return "".join(f"<code>{p}</code>" if i % 2 else p for i, p in enumerate(parts))


_CSS = """body{font-family:Segoe UI,Arial,sans-serif;margin:2rem auto;max-width:1200px;padding:0 1rem;color:#1b1b1b}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:.9rem}th,td{border:1px solid #ccc;
padding:4px 6px;text-align:left;vertical-align:top}th{background:#f2f2f2}pre{background:#f7f7f7;padding:.6rem;
overflow:auto;white-space:pre-wrap}h2{border-bottom:2px solid #333;padding-bottom:.2rem;margin-top:2rem}
code{background:#f0f0f0;padding:0 3px}"""


def to_html(blocks: list[Block], lang: str = "en") -> str:
    """HTML estático, sem JavaScript e sem recursos externos."""
    out = [f'<!doctype html><html lang="{html.escape(lang)}"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           f"<title>{html.escape(str(blocks[0][1]))}</title><style>{_CSS}</style></head><body>"]
    for blk in blocks:
        kind = blk[0]
        if kind in ("h1", "h2", "h3"):
            out.append(f"<{kind}>{_inline(blk[1])}</{kind}>")
        elif kind == "p":
            out.append(f"<p>{_inline(blk[1])}</p>")
        elif kind in ("ul", "ol"):
            out.append(f"<{kind}>" + "".join(f"<li>{_inline(str(x))}</li>" for x in blk[1]) + f"</{kind}>")
        elif kind == "pre":
            out.append(f"<pre>{html.escape(blk[1])}</pre>")
        elif kind == "table":
            if not blk[2]:
                out.append("<p><em>(empty)</em></p>")
                continue
            head = "".join(f"<th>{html.escape(h)}</th>" for h in blk[1])
            rows = "".join("<tr>" + "".join(f"<td>{_inline(str(c))}</td>" for c in r) + "</tr>" for r in blk[2])
            out.append(f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
    out.append("</body></html>")
    return "\n".join(out)


def render(doc: dict[str, Any], fmt: str, lang: str = "en") -> str:
    if fmt == "json":
        return json.dumps(doc, indent=2, ensure_ascii=False)
    blocks = build_blocks(doc, lang)
    if fmt == "markdown":
        return to_markdown(blocks)
    if fmt == "html":
        return to_html(blocks, lang)
    raise ValueError(f"Unknown format: {fmt}")
