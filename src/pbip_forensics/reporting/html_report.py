"""Relatório HTML interativo e autocontido (um único arquivo, sem recursos externos).

- Todo texto vindo do projeto é escapado (conteúdo tratado como dado não confiável).
- O JavaScript embutido apenas filtra/expande elementos já renderizados; não há
  rede, eval nem dados injetados como código. Sem JavaScript o relatório continua
  completo e legível.
- Tema claro/escuro automático e CSS de impressão.
"""

from __future__ import annotations

import html
from collections import Counter, defaultdict
from typing import Any

from pbip_forensics.reporting.insights import compute_insights

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
STATUS_ORDER = ["confirmed", "potential", "inconclusive"]

T = {
    "en": {
        "title": "Audit Report", "summary": "Summary", "priorities": "Top priorities", "rules": "Rules overview",
        "findings": "Findings", "relationships": "Relationships", "dax": "DAX", "visuals": "Visuals",
        "performance": "Performance", "impact": "Change impact", "hypotheses": "Root cause", "actions": "Actions",
        "limitations": "Limitations", "inventory": "Inventory", "search": "Search title, object, path or evidence…",
        "all_status": "All statuses", "all_cat": "All categories", "all_rules": "All rules", "expand": "Expand all",
        "collapse": "Collapse all", "showing": "Showing", "of": "of", "explanation": "Explanation",
        "impact_l": "Impact", "recommendation": "Recommendation", "verification": "How to verify",
        "evidence": "Evidence", "source": "Source", "none": "Nothing to show in this section.",
        "no_perf": "No Performance Analyzer log was provided. No runtime measurements are available; static "
                   "performance risks are listed in Findings (category “DAX performance”).",
        "no_impact": "No version comparison was run. Use the diff command/script to compare two versions.",
        "no_hyp": "No investigation was run. Use investigate (CLI) or pbip_visual_deps.py --from-table … to get "
                  "ranked root-cause hypotheses.",
        "total": "Findings", "confirmed": "confirmed", "potential": "potential", "inconclusive": "inconclusive",
        "count": "Count", "rule": "Rule", "category": "Category", "max_sev": "Highest", "example": "Example",
        "status": "Status", "generated": "Generated (UTC)", "readonly": "Read-only analysis",
        "applies": "applies to", "items": "finding(s)", "bindings": "bindings", "broken": "Problem bindings",
        "full_map": "Full dependency map", "measure": "Measure", "depth": "Depth", "depends": "Depends on",
        "from": "From", "to": "To", "active": "Active", "cross": "Cross filter", "card": "Cardinality",
        "visual": "Visual", "type": "Type", "total_ms": "Total ms", "page": "Page", "field": "Field",
        "table": "Table", "kind": "Kind", "usage": "Usage", "rank": "Rank", "conf": "confidence",
        "steps": "Verification steps", "det_evidence": "Deterministic evidence", "dependents": "Dependent measures",
        "affected": "Affected visuals", "changes": "Changes", "object": "Object", "change": "Change",
        "details": "Details", "footer": "Static analysis: DAX is not executed and no data values are read. "
                                         "Findings marked potential require verification in Power BI.",
        "filter_rule": "Filter findings by this rule",
        "overview": "Overview", "health": "Health score", "plain": "In plain words", "wins": "What to do first",
        "model_map": "Model map", "measures_t": "Measures", "pages_t": "Pages", "sources": "Data sources",
        "score_note": "Indicative score from the findings (not a quality certificate). Formula: ",
        "legend_dim": "Dimension", "legend_fact": "Fact", "legend_bridge": "Bridge", "legend_disc": "Disconnected",
        "legend_inactive": "inactive", "legend_both": "bidirectional", "legend_amb": "ambiguous path",
        "auto_hidden": "auto date tables hidden", "complex_t": "Most complex measures", "hubs_t": "Central measures",
        "folders_t": "Display folders", "score": "Score", "calls": "Functions", "iters": "Iterators",
        "nest": "Nesting", "used_m": "Used by measures", "used_v": "Used in visuals", "data_vis": "data visuals",
        "slicers": "slicers", "custom": "custom", "filters": "filters", "measures_l": "measures",
        "broken_l": "broken bindings", "tables_l": "Tables used", "no_fmt": "without format",
        "no_folder": "without folder", "max_depth": "max dependency depth", "effort": "Effort",
    },
    "pt-BR": {
        "title": "Relatório de Auditoria", "summary": "Resumo", "priorities": "Prioridades", "rules": "Visão por regra",
        "findings": "Achados", "relationships": "Relacionamentos", "dax": "DAX", "visuals": "Visuais",
        "performance": "Desempenho", "impact": "Impacto de mudanças", "hypotheses": "Causa raiz", "actions": "Ações",
        "limitations": "Limitações", "inventory": "Inventário", "search": "Buscar título, objeto, caminho ou evidência…",
        "all_status": "Todos os status", "all_cat": "Todas as categorias", "all_rules": "Todas as regras",
        "expand": "Expandir tudo", "collapse": "Recolher tudo", "showing": "Exibindo", "of": "de",
        "explanation": "Explicação", "impact_l": "Impacto", "recommendation": "Recomendação",
        "verification": "Como verificar", "evidence": "Evidências", "source": "Origem",
        "none": "Nada a exibir nesta seção.",
        "no_perf": "Nenhum log do Performance Analyzer foi informado. Não há medições reais; os riscos estáticos de "
                   "desempenho estão em Achados (categoria “DAX performance”).",
        "no_impact": "Nenhuma comparação de versões foi executada. Use o comando/script diff.",
        "no_hyp": "Nenhuma investigação foi executada. Use investigate (CLI) ou pbip_visual_deps.py --from-table … "
                  "para obter hipóteses ordenadas.",
        "total": "Achados", "confirmed": "confirmados", "potential": "potenciais", "inconclusive": "inconclusivos",
        "count": "Qtde", "rule": "Regra", "category": "Categoria", "max_sev": "Maior", "example": "Exemplo",
        "status": "Status", "generated": "Gerado (UTC)", "readonly": "Análise somente leitura",
        "applies": "aplica-se a", "items": "achado(s)", "bindings": "vínculos", "broken": "Vínculos com problema",
        "full_map": "Mapa completo de dependências", "measure": "Medida", "depth": "Profundidade",
        "depends": "Depende de", "from": "De", "to": "Para", "active": "Ativo", "cross": "Filtro cruzado",
        "card": "Cardinalidade", "visual": "Visual", "type": "Tipo", "total_ms": "Total ms", "page": "Página",
        "field": "Campo", "table": "Tabela", "kind": "Tipo", "usage": "Uso", "rank": "Posição", "conf": "confiança",
        "steps": "Passos de verificação", "det_evidence": "Evidência determinística",
        "dependents": "Medidas dependentes", "affected": "Visuais afetados", "changes": "Mudanças",
        "object": "Objeto", "change": "Mudança", "details": "Detalhes",
        "footer": "Análise estática: DAX não é executado e nenhum dado é lido. Achados potenciais exigem "
                  "verificação no Power BI.",
        "filter_rule": "Filtrar achados por esta regra",
        "overview": "Visão geral", "health": "Nota de saúde", "plain": "Em palavras simples",
        "wins": "O que fazer primeiro", "model_map": "Mapa do modelo", "measures_t": "Medidas", "pages_t": "Páginas",
        "sources": "Fontes de dados",
        "score_note": "Nota indicativa calculada a partir dos achados (não é certificado de qualidade). Fórmula: ",
        "legend_dim": "Dimensão", "legend_fact": "Fato", "legend_bridge": "Ponte", "legend_disc": "Desconectada",
        "legend_inactive": "inativo", "legend_both": "bidirecional", "legend_amb": "caminho ambíguo",
        "auto_hidden": "tabelas automáticas de data ocultas", "complex_t": "Medidas mais complexas",
        "hubs_t": "Medidas centrais", "folders_t": "Pastas de exibição", "score": "Pontuação", "calls": "Funções",
        "iters": "Iteradores", "nest": "Aninhamento", "used_m": "Usada por medidas", "used_v": "Usada em visuais",
        "data_vis": "visuais com dados", "slicers": "segmentações", "custom": "personalizados", "filters": "filtros",
        "measures_l": "medidas", "broken_l": "vínculos quebrados", "tables_l": "Tabelas usadas",
        "no_fmt": "sem formato", "no_folder": "sem pasta", "max_depth": "profundidade máx. de dependência",
        "effort": "Esforço",
    },
}

_LOGO = ('<svg viewBox="0 0 64 64" width="40" height="40" aria-hidden="true"><path d="M32 3 7 12v18c0 15 '
         '10.5 26.5 25 31 14.5-4.5 25-16 25-31V12z" fill="var(--brand)"/><rect x="17" y="18" width="30" height="22" '
         'rx="3" fill="#fff"/><rect x="21" y="30" width="4" height="7" fill="#F2A900"/><rect x="27" y="26" width="4" '
         'height="11" fill="#F2A900"/><rect x="33" y="22" width="4" height="15" fill="#F2A900"/><circle cx="41" '
         'cy="41" r="7" fill="none" stroke="#0B1F44" stroke-width="3"/><path d="m46 46 6 6" stroke="#F2A900" '
         'stroke-width="4" stroke-linecap="round"/></svg>')

_CSS = """
:root{--bg:#f5f7fb;--panel:#fff;--ink:#14213d;--muted:#5b6478;--line:#e3e7ef;--brand:#0b5ed7;--brand2:#f2a900;
--crit:#7a0b2e;--high:#d1242f;--med:#d97706;--low:#2563eb;--info:#64748b;--ok:#15803d;--chip:#eef2f8;
--shadow:0 1px 2px rgba(16,24,40,.06),0 2px 8px rgba(16,24,40,.06)}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--panel:#161b22;--ink:#e6edf3;--muted:#9aa4b2;
--line:#2a313c;--chip:#1f2630;--shadow:none}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
a{color:var(--brand)}code,pre{font-family:Consolas,"Cascadia Mono",Menlo,monospace;font-size:12.5px}
header.top{background:linear-gradient(120deg,#0b1f44,#0b5ed7);color:#fff;padding:22px 28px 18px}
.top .row{display:flex;gap:14px;align-items:center;flex-wrap:wrap}.top h1{margin:0;font-size:22px}
.top .sub{opacity:.85;font-size:13px}.meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.meta span{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.25);border-radius:999px;
padding:3px 10px;font-size:12px}
nav.tabs{position:sticky;top:0;z-index:5;background:var(--panel);border-bottom:1px solid var(--line);
display:flex;gap:2px;overflow-x:auto;padding:0 18px;box-shadow:var(--shadow)}
nav.tabs a{padding:11px 12px;text-decoration:none;color:var(--muted);white-space:nowrap;font-weight:600;
border-bottom:3px solid transparent}nav.tabs a:hover{color:var(--ink);border-color:var(--brand2)}
main{max-width:1280px;margin:0 auto;padding:22px 20px 60px}
section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;
margin-bottom:18px;box-shadow:var(--shadow);scroll-margin-top:56px}
h2{font-size:17px;margin:0 0 12px;display:flex;align-items:center;gap:8px}
h2 .n{background:var(--chip);color:var(--muted);border-radius:999px;font-size:12px;padding:1px 9px}
h3{font-size:14px;margin:16px 0 8px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.kpi{border:1px solid var(--line);border-radius:10px;padding:10px 12px;border-top:4px solid var(--info)}
.kpi b{display:block;font-size:24px;line-height:1.2}.kpi span{color:var(--muted);font-size:12px;text-transform:uppercase;
letter-spacing:.03em}
.kpi.CRITICAL{border-top-color:var(--crit)}.kpi.HIGH{border-top-color:var(--high)}.kpi.MEDIUM{border-top-color:var(--med)}
.kpi.LOW{border-top-color:var(--low)}.kpi.total{border-top-color:var(--brand)}
.stack{display:flex;height:12px;border-radius:999px;overflow:hidden;background:var(--chip);margin:14px 0 6px}
.stack i{display:block}.legend{display:flex;flex-wrap:wrap;gap:12px;color:var(--muted);font-size:12px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;vertical-align:middle}
.bg-CRITICAL{background:var(--crit)}.bg-HIGH{background:var(--high)}.bg-MEDIUM{background:var(--med)}
.bg-LOW{background:var(--low)}.bg-INFO{background:var(--info)}
.inv{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin-top:14px}
.inv div{background:var(--chip);border-radius:8px;padding:8px 10px}.inv b{display:block;font-size:18px}
.inv span{font-size:12px;color:var(--muted)}
.badge{display:inline-block;border-radius:6px;padding:1px 7px;font-size:11px;font-weight:700;color:#fff;
letter-spacing:.02em;white-space:nowrap}
.st{display:inline-block;border-radius:6px;padding:0 7px;font-size:11px;border:1px solid var(--line);color:var(--muted)}
.st.confirmed{border-color:var(--ok);color:var(--ok)}.st.inconclusive{border-style:dashed}
.rule{font-family:Consolas,Menlo,monospace;font-size:12px;color:var(--muted)}
.prio{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:10px}
.prio .card{border:1px solid var(--line);border-left:4px solid var(--high);border-radius:10px;padding:10px 12px}
.prio .card.CRITICAL{border-left-color:var(--crit)}.prio .card p{margin:6px 0 0;color:var(--muted);font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:7px 9px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;background:var(--chip);
position:sticky;top:44px}tbody tr:hover{background:var(--chip)}
.scroll{max-height:520px;overflow:auto;border:1px solid var(--line);border-radius:8px}.scroll th{top:0}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.toolbar input,.toolbar select{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:8px;
padding:7px 10px;font:inherit}.toolbar input{flex:1 1 260px}
.chipbtn{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:999px;padding:5px 11px;
cursor:pointer;font:inherit;font-size:12px;font-weight:600}.chipbtn[aria-pressed=false]{opacity:.45}
.btn{border:1px solid var(--line);background:var(--chip);color:var(--ink);border-radius:8px;padding:6px 11px;cursor:pointer;
font:inherit;font-size:12px}.count{color:var(--muted);font-size:12px;margin-left:auto}
.finding{border:1px solid var(--line);border-left:4px solid var(--info);border-radius:10px;margin-bottom:8px;
background:var(--panel)}.finding.CRITICAL{border-left-color:var(--crit)}.finding.HIGH{border-left-color:var(--high)}
.finding.MEDIUM{border-left-color:var(--med)}.finding.LOW{border-left-color:var(--low)}
.finding summary{list-style:none;cursor:pointer;padding:10px 12px;display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.finding summary::-webkit-details-marker{display:none}.finding summary .t{font-weight:600;flex:1 1 420px}
.finding .body{padding:0 14px 12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}
.finding .body div{background:var(--chip);border-radius:8px;padding:8px 10px}.finding .body h4{margin:0 0 3px;font-size:11px;
text-transform:uppercase;color:var(--muted);letter-spacing:.04em}.finding .body .wide{grid-column:1/-1}
.finding ul{margin:0;padding-left:18px}.src{color:var(--muted);font-size:12px;word-break:break-all}
.perfrow{display:grid;grid-template-columns:minmax(160px,260px) 1fr 80px;gap:10px;align-items:center;margin:6px 0}
.perfbar{display:flex;height:14px;border-radius:4px;overflow:hidden;background:var(--chip)}
.p-dax{background:#0b5ed7}.p-dq{background:#7c3aed}.p-vis{background:#f2a900}.p-oth{background:#94a3b8}
.hyp{border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:8px 0}
.conf{font-size:11px;font-weight:700;border-radius:6px;padding:1px 7px;color:#fff}.conf.high{background:var(--high)}
.conf.medium{background:var(--med)}.conf.low{background:var(--info)}
pre{background:var(--chip);border-radius:8px;padding:10px;white-space:pre-wrap;word-break:break-word;margin:6px 0}
.notice{background:var(--chip);border-left:4px solid var(--brand2);border-radius:8px;padding:10px 12px;color:var(--muted)}
ol.actions li{margin:6px 0}.muted{color:var(--muted)}footer{text-align:center;color:var(--muted);font-size:12px;padding:20px}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--high);font-weight:600}
.gauges{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.gauge{border:1px solid var(--line);border-radius:12px;padding:12px;text-align:center}.gauge svg{display:block;margin:0 auto}.gauge text{fill:var(--ink)}
.gauge .lbl{font-weight:600;margin-top:6px}.gauge .g{font-size:12px;color:var(--muted)}
.gauge.main{background:linear-gradient(180deg,var(--chip),transparent)}
.g-good{stroke:#15803d}.g-attention{stroke:#d97706}.g-critical{stroke:#d1242f}.g-not_measured{stroke:#94a3b8}
.story{font-size:15px;line-height:1.6}.story li{margin:6px 0}
.wins{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px}
.win{border:1px solid var(--line);border-radius:10px;padding:10px 12px}.win h4{margin:4px 0 6px;font-size:14px}
.eff{font-size:11px;font-weight:700;border-radius:6px;padding:1px 7px;background:var(--chip);color:var(--ink)}
.eff.quick{background:#dcfce7;color:#166534}.eff.medium{background:#fef3c7;color:#92400e}.eff.structural{background:#fee2e2;color:#991b1b}
.diagram{overflow:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel)}
.diagram text{font-family:"Segoe UI",system-ui,sans-serif;fill:var(--ink)}
.pages{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}
.pg{border:1px solid var(--line);border-radius:10px;padding:10px 12px}.pg h4{margin:0 0 6px}
.pg .nums{display:flex;flex-wrap:wrap;gap:6px}.pg .nums span{background:var(--chip);border-radius:6px;padding:1px 7px;font-size:12px}
.hbar{display:grid;grid-template-columns:minmax(120px,240px) 1fr 40px;gap:8px;align-items:center;margin:4px 0;font-size:13px}
.hbar div{height:10px;border-radius:4px;background:var(--brand)}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(480px,100%),1fr));gap:16px}.two>div{min-width:0}.two td:first-child{min-width:170px}
@media print{nav.tabs,.toolbar{display:none}body{background:#fff}section{box-shadow:none;break-inside:avoid-page}
th{position:static}.scroll{max-height:none;overflow:visible}}
"""

_JS = """
(function(){
var q=document.getElementById('q'),st=document.getElementById('fst'),ca=document.getElementById('fcat'),
ru=document.getElementById('frule'),cnt=document.getElementById('cnt'),items=[].slice.call(document.querySelectorAll('.finding')),
sev={};[].forEach.call(document.querySelectorAll('.chipbtn[data-sev]'),function(b){sev[b.dataset.sev]=true;
b.addEventListener('click',function(){sev[b.dataset.sev]=!sev[b.dataset.sev];b.setAttribute('aria-pressed',sev[b.dataset.sev]);apply();});});
function apply(){var t=(q.value||'').toLowerCase(),n=0;items.forEach(function(e){var ok=sev[e.dataset.sev]&&
(!st.value||e.dataset.status===st.value)&&(!ca.value||e.dataset.cat===ca.value)&&(!ru.value||e.dataset.rule===ru.value)&&
(!t||e.dataset.text.indexOf(t)>=0);e.style.display=ok?'':'none';if(ok)n++;});cnt.textContent=n;}
[q,st,ca,ru].forEach(function(e){e.addEventListener('input',apply);});
document.getElementById('exp').addEventListener('click',function(){items.forEach(function(e){if(e.style.display!=='none')e.open=true;});});
document.getElementById('col').addEventListener('click',function(){items.forEach(function(e){e.open=false;});});
[].forEach.call(document.querySelectorAll('[data-rulefilter]'),function(a){a.addEventListener('click',function(){
ru.value=a.dataset.rulefilter;apply();});});
window.addEventListener('beforeprint',function(){items.forEach(function(e){e.open=true;});});apply();})();
"""


def e(value: Any) -> str:
    """Escapa qualquer valor para HTML (texto e atributos)."""
    return html.escape("" if value is None else str(value), quote=True)


def _badge(sev: str) -> str:
    return f'<span class="badge bg-{e(sev)}">{e(sev)}</span>'


def _table(headers: list[str], rows: list[list[str]], raw: bool = False, scroll: bool = True) -> str:
    if not rows:
        return ""
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c if raw else e(c)}</td>" for c in r) + "</tr>" for r in rows)
    tbl = f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
    return f'<div class="scroll">{tbl}</div>' if scroll else tbl


def _section(sid: str, title: str, content: str, count: int | None = None) -> str:
    n = f' <span class="n">{count}</span>' if count is not None else ""
    return f'<section id="{sid}"><h2>{e(title)}{n}</h2>{content}</section>'


def _finding_card(f: dict[str, Any], L: dict[str, str]) -> str:
    loc = f"{f.get('path', '')}" + (f":{f['line']}" if f.get("line") else "")
    text = " ".join([f.get("title", ""), f.get("object_ref", ""), loc, *f.get("evidence", [])]).lower()
    ev = "".join(f"<li>{e(x)}</li>" for x in f.get("evidence", []))
    return (
        f'<details class="finding {e(f["severity"])}" data-sev="{e(f["severity"])}" data-status="{e(f["status"])}" '
        f'data-cat="{e(f.get("category"))}" data-rule="{e(f.get("rule_id"))}" data-text="{e(text)}">'
        f'<summary>{_badge(f["severity"])} <span class="st {e(f["status"])}">{e(f["status"])}</span> '
        f'<span class="t">{e(f["title"])}</span><span class="rule">{e(f["id"])}</span></summary>'
        f'<div class="body"><div class="wide"><h4>{e(L["source"])}</h4><span class="src">{e(loc)} · '
        f'{e(f.get("object_ref"))}</span></div>'
        f'<div class="wide"><h4>{e(L["evidence"])}</h4><ul>{ev}</ul></div>'
        f'<div><h4>{e(L["explanation"])}</h4>{e(f.get("explanation"))}</div>'
        f'<div><h4>{e(L["impact_l"])}</h4>{e(f.get("impact"))}</div>'
        f'<div><h4>{e(L["recommendation"])}</h4>{e(f.get("recommendation"))}</div>'
        f'<div><h4>{e(L["verification"])}</h4>{e(f.get("verification"))}</div></div></details>'
    )


def _gauge(score: int | None, grade: str, label: str, grade_label: str, main: bool = False) -> str:
    r, c = 34, 2 * 3.14159 * 34
    val = 0 if score is None else max(0, min(100, score))
    txt = "–" if score is None else str(score)
    return (f'<div class="gauge{" main" if main else ""}"><svg width="96" height="96" viewBox="0 0 96 96" '
            f'role="img" aria-label="{e(label)} {e(txt)}"><circle cx="48" cy="48" r="{r}" fill="none" '
            f'stroke="var(--chip)" stroke-width="10"/><circle class="g-{e(grade)}" cx="48" cy="48" r="{r}" '
            f'fill="none" stroke-width="10" stroke-linecap="round" stroke-dasharray="{c * val / 100:.1f} {c:.1f}" '
            f'transform="rotate(-90 48 48)"/><text x="48" y="55" text-anchor="middle" font-size="22" '
            f'font-weight="700">{e(txt)}</text></svg><div class="lbl">{e(label)}</div>'
            f'<div class="g">{e(grade_label)}</div></div>')


def _diagram(g: dict[str, Any], L: dict[str, str]) -> str:
    """Diagrama em camadas: dimensões (topo) → pontes → fatos → desconectadas."""
    nodes = g.get("nodes", [])
    if not nodes:
        return ""
    layer_of = {"dimension": 0, "bridge": 1, "fact": 2, "disconnected": 3}
    layers: dict[int, list[str]] = {}
    for n in sorted(nodes, key=lambda n: n["name"].lower()):
        layers.setdefault(layer_of.get(n["role"], 3), []).append(n["name"])
    nbr: dict[str, set[str]] = {n["name"]: set() for n in nodes}
    for ed in g.get("edges", []):
        nbr[ed["from"]].add(ed["to"])
        nbr[ed["to"]].add(ed["from"])
    W, H, GX, GY, PAD = 178, 46, 26, 96, 20
    for _ in range(4):  # ordenação por baricentro (reduz cruzamentos)
        pos = {name: i for row in layers.values() for i, name in enumerate(row)}
        for k in sorted(layers):
            layers[k].sort(key=lambda nm: (sum(pos[x] for x in nbr[nm]) / len(nbr[nm])) if nbr[nm] else 1e9)
    width = max(len(r) for r in layers.values()) * (W + GX) + PAD * 2
    xy: dict[str, tuple[float, float]] = {}
    for row_i, k in enumerate(sorted(layers)):
        row = layers[k]
        off = (width - len(row) * (W + GX) + GX) / 2
        for i, nm in enumerate(row):
            xy[nm] = (off + i * (W + GX), PAD + row_i * (H + GY))
    height = PAD * 2 + len(layers) * (H + GY) - GY
    colors = {"dimension": "#0b5ed7", "fact": "#f2a900", "bridge": "#7c3aed", "disconnected": "#94a3b8"}
    svg = [f'<svg width="{width:.0f}" height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" '
           'xmlns="http://www.w3.org/2000/svg"><defs>'
           '<marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
           '<path d="M0 0L10 5L0 10z" fill="#64748b"/></marker>'
           '<marker id="arO" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
           '<path d="M0 0L10 5L0 10z" fill="#d97706"/></marker></defs>']
    for ed in g.get("edges", []):
        (x1, y1), (x2, y2) = xy[ed["to"]], xy[ed["from"]]  # filtro: lado "one" (to) → lado "many" (from)
        ax, ay, bx, by = x1 + W / 2, y1 + H / 2, x2 + W / 2, y2 + H / 2
        if y1 < y2:
            ay, by = y1 + H, y2
        elif y1 > y2:
            ay, by = y1, y2 + H
        else:
            ay = by = y1 + H
        mid = (ay + by) / 2 if y1 != y2 else ay + 40
        color = "#d1242f" if ed["ambiguous"] else "#d97706" if ed["both"] else "#64748b"
        dash = ' stroke-dasharray="6 5"' if not ed["active"] else ""
        mk = "arO" if ed["both"] and not ed["ambiguous"] else "ar"
        start = f' marker-start="url(#{mk})"' if ed["both"] else ""
        svg.append(f'<path d="M{ax:.0f} {ay:.0f} C {ax:.0f} {mid:.0f}, {bx:.0f} {mid:.0f}, {bx:.0f} {by:.0f}" '
                   f'fill="none" stroke="{color}" stroke-width="{3 if ed["ambiguous"] else 1.6}"{dash}'
                   f' marker-end="url(#{mk})"{start} opacity="{0.45 if not ed["active"] else 0.9}">'
                   f'<title>{e(ed["label"])} · {e(ed["card"])}{" · inactive" if not ed["active"] else ""}</title></path>')
    for n in nodes:
        x, y = xy[n["name"]]
        name = n["name"] if len(n["name"]) <= 24 else n["name"][:23] + "…"
        svg.append(f'<g><title>{e(n["name"])} · {e(n["role"])} · {n["columns"]} cols · {n["measures"]} measures</title>'
                   f'<rect x="{x:.0f}" y="{y:.0f}" width="{W}" height="{H}" rx="8" fill="var(--panel)" '
                   f'stroke="{colors.get(n["role"], "#94a3b8")}" stroke-width="2"/>'
                   f'<rect x="{x:.0f}" y="{y:.0f}" width="6" height="{H}" rx="3" fill="{colors.get(n["role"], "#94a3b8")}"/>'
                   f'<text x="{x + 14:.0f}" y="{y + 19:.0f}" font-size="12.5" font-weight="600">{e(name)}</text>'
                   f'<text x="{x + 14:.0f}" y="{y + 36:.0f}" font-size="11" opacity=".7">{n["columns"]} cols · '
                   f'{n["measures"]} meas.{" · calc" if n["calculated"] else ""}</text></g>')
    svg.append("</svg>")
    legend = (f'<div class="legend"><span><i class="dot" style="background:#0b5ed7"></i>{e(L["legend_dim"])}</span>'
              f'<span><i class="dot" style="background:#7c3aed"></i>{e(L["legend_bridge"])}</span>'
              f'<span><i class="dot" style="background:#f2a900"></i>{e(L["legend_fact"])}</span>'
              f'<span><i class="dot" style="background:#94a3b8"></i>{e(L["legend_disc"])}</span>'
              f'<span>- - - {e(L["legend_inactive"])}</span><span style="color:#d97706">⇄ {e(L["legend_both"])}</span>'
              f'<span style="color:#d1242f">━ {e(L["legend_amb"])}</span>'
              + (f'<span>· {g["hidden_auto"]} {e(L["auto_hidden"])}</span>' if g.get("hidden_auto") else "")
              + "</div>")
    return legend + f'<div class="diagram">{"".join(svg)}</div>'


def _overview(ins: dict[str, Any], L: dict[str, str]) -> str:
    sc = ins["scores"]
    gauges = _gauge(sc["overall"], sc["grade"], L["health"], sc["grade_label"], True) + "".join(
        _gauge(a["score"], a["grade"], a["label"], a["grade_label"]) for a in sc["areas"])
    story = "".join(f"<li>{e(x)}</li>" for x in ins["narrative"])
    wins = "".join(
        f'<div class="win"><span class="eff {e(w["effort"])}">{e(w["effort_label"])}</span> {_badge(w["severity"])} '
        f'<span class="rule">{e(w["rule_id"])} · {w["count"]}×</span><h4>{e(w["title"])}</h4>'
        f'<div class="muted">{e(w["recommendation"])}</div>'
        f'<a href="#findings" data-rulefilter="{e(w["rule_id"])}">→ {e(L["findings"])}</a></div>'
        for w in ins["quick_wins"])
    return (f'<div class="gauges">{gauges}</div><p class="muted" style="font-size:12px">{e(L["score_note"])}'
            f'{e(sc["formula"])}</p><h3>{e(L["plain"])}</h3><ul class="story">{story}</ul>'
            + (f'<h3>{e(L["wins"])}</h3><div class="wins">{wins}</div>' if wins else ""))


def _measures(ins: dict[str, Any], L: dict[str, str]) -> str:
    ms = ins["measures"]
    if not ms["total"]:
        return f'<p class="muted">{e(L["none"])}</p>'
    chips = (f'<p><b>{ms["total"]}</b> {e(L["measures_l"])} · {ms["no_format"]} {e(L["no_fmt"])} · '
             f'{ms["no_folder"]} {e(L["no_folder"])} · {e(L["max_depth"])}: {ms["max_depth"]}</p>')
    cx = _table([L["measure"], L["score"], L["calls"], L["iters"], L["nest"], L["depth"], L["used_m"], L["used_v"]],
                [[f"[{x['name']}]", str(x["score"]), str(x["calls"]), str(x["iterators"]), str(x["max_nesting"]),
                  str(x["depth"]), str(x["used_by_measures"]), str(x["used_in_visuals"])] for x in ms["complex"]])
    hubs = _table([L["measure"], L["used_m"], L["used_v"]],
                  [[f"[{x['name']}]", str(x["used_by_measures"]), str(x["used_in_visuals"])] for x in ms["hubs"]])
    mx = max((c for _, c in ms["folders"]), default=1)
    folders = "".join(f'<div class="hbar"><span>{e(f)}</span><div style="width:{100 * c / mx:.0f}%"></div>'
                      f'<b>{c}</b></div>' for f, c in ms["folders"])
    return (chips + f'<div class="two"><div><h3>{e(L["complex_t"])}</h3>{cx}</div>'
            f'<div><h3>{e(L["hubs_t"])}</h3>{hubs}<h3>{e(L["folders_t"])}</h3>{folders}</div></div>')


def _pages(ins: dict[str, Any], L: dict[str, str]) -> str:
    cards = []
    for p in ins["pages"]:
        sev = " ".join(f'{_badge(k)} {v}' for k, v in sorted(p["findings"].items(), key=lambda kv: SEV_ORDER.index(kv[0]))
                       if k != "INFO")
        cards.append(
            f'<div class="pg"><h4>{e(p["page"])}</h4><div class="nums"><span>{p["visuals"]} {e(L["visuals"]).lower()}'
            f'</span><span>{p["data_visuals"]} {e(L["data_vis"])}</span><span>{p["slicers"]} {e(L["slicers"])}</span>'
            f'<span>{p["filters"]} {e(L["filters"])}</span><span>{p["measures"]} {e(L["measures_l"])}</span>'
            + (f'<span>{p["custom"]} {e(L["custom"])}</span>' if p["custom"] else "")
            + (f'<span class="bad">{p["broken"]} {e(L["broken_l"])}</span>' if p["broken"] else "")
            + f'</div><p class="muted" style="margin:6px 0 0">{e(L["tables_l"])}: {e(", ".join(p["tables"]) or "—")}</p>'
            + (f"<div>{sev}</div>" if sev else "") + "</div>")
    return f'<div class="pages">{"".join(cards)}</div>' if cards else ""


def to_html_report(doc: dict[str, Any], lang: str = "en") -> str:
    """Gera o relatório HTML completo a partir do documento de auditoria."""
    L = T.get(lang, T["en"])
    findings: list[dict[str, Any]] = doc.get("findings", []) or []
    inv = doc.get("inventory", {}) or {}
    counts = inv.get("counts", {}) or {}
    sev = Counter(f["severity"] for f in findings)
    st = Counter(f["status"] for f in findings)
    total = len(findings)
    scope = doc.get("scope", {}) or {}
    ins = compute_insights(doc, lang)
    parts: list[str] = [_section("overview", L["overview"], _overview(ins, L))]

    # ---------------------------------------------------------------- resumo
    kpis = f'<div class="kpi total"><b>{total}</b><span>{e(L["total"])}</span></div>' + "".join(
        f'<div class="kpi {s}"><b>{sev.get(s, 0)}</b><span>{s}</span></div>' for s in SEV_ORDER)
    stack = "".join(f'<i class="bg-{s}" style="width:{100 * sev.get(s, 0) / total:.2f}%"></i>'
                    for s in SEV_ORDER if total and sev.get(s)) if total else ""
    legend = " ".join(f'<span><i class="dot bg-{s}"></i>{s} {sev.get(s, 0)}</span>' for s in SEV_ORDER)
    stx = " · ".join(f"{st.get(s, 0)} {e(L[s])}" for s in STATUS_ORDER)
    inv_cards = "".join(f'<div><b>{e(v)}</b><span>{e(k.replace("_", " "))}</span></div>' for k, v in counts.items())
    parts.append(_section("summary", L["summary"],
                          f'<div class="kpis">{kpis}</div><div class="stack">{stack}</div>'
                          f'<div class="legend">{legend}<span>· {stx}</span></div><div class="inv">{inv_cards}</div>'))

    # ----------------------------------------------------------- prioridades
    prio = sorted([f for f in findings if f["severity"] in ("CRITICAL", "HIGH")],
                  key=lambda f: (SEV_ORDER.index(f["severity"]), STATUS_ORDER.index(f["status"])))[:9]
    if prio:
        cards = "".join(
            f'<div class="card {e(f["severity"])}">{_badge(f["severity"])} <span class="st {e(f["status"])}">'
            f'{e(f["status"])}</span> <span class="rule">{e(f["rule_id"])}</span><div><b>{e(f["title"])}</b></div>'
            f'<p>{e(f.get("recommendation"))}</p></div>' for f in prio)
        parts.append(_section("priorities", L["priorities"], f'<div class="prio">{cards}</div>'))

    # --------------------------------------------------------- visão por regra
    by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        by_rule[f["rule_id"]].append(f)
    rule_rows = []
    for rid, items in sorted(by_rule.items(), key=lambda kv: (min(SEV_ORDER.index(x["severity"]) for x in kv[1]),
                                                              -len(kv[1]), kv[0])):
        worst = min((x["severity"] for x in items), key=SEV_ORDER.index)
        mix = Counter(x["status"] for x in items)
        rule_rows.append([
            f'<a href="#findings" data-rulefilter="{e(rid)}" title="{e(L["filter_rule"])}"><code>{e(rid)}</code></a>',
            e(items[0].get("category")), _badge(worst), str(len(items)),
            e(", ".join(f"{v} {k}" for k, v in mix.items())), e(items[0]["title"])])
    parts.append(_section("rules", L["rules"], _table([L["rule"], L["category"], L["max_sev"], L["count"],
                                                       L["status"], L["example"]], rule_rows, raw=True)
                          or f'<p class="muted">{e(L["none"])}</p>', len(by_rule)))

    # ------------------------------------------------------------- achados
    cats = sorted({f.get("category", "") for f in findings})
    toolbar = (
        f'<div class="toolbar"><input id="q" type="search" placeholder="{e(L["search"])}" aria-label="search">'
        + "".join(f'<button class="chipbtn" type="button" data-sev="{s}" aria-pressed="true">'
                  f'<i class="dot bg-{s}"></i>{s}</button>' for s in SEV_ORDER)
        + f'<select id="fst"><option value="">{e(L["all_status"])}</option>'
        + "".join(f'<option value="{s}">{e(s)}</option>' for s in STATUS_ORDER) + "</select>"
        + f'<select id="fcat"><option value="">{e(L["all_cat"])}</option>'
        + "".join(f'<option value="{e(c)}">{e(c)}</option>' for c in cats) + "</select>"
        + f'<select id="frule"><option value="">{e(L["all_rules"])}</option>'
        + "".join(f'<option value="{e(r)}">{e(r)}</option>' for r in sorted(by_rule)) + "</select>"
        + f'<button class="btn" id="exp" type="button">{e(L["expand"])}</button>'
        + f'<button class="btn" id="col" type="button">{e(L["collapse"])}</button>'
        + f'<span class="count">{e(L["showing"])} <b id="cnt">{total}</b> {e(L["of"])} {total}</span></div>')
    cards = "".join(_finding_card(f, L) for f in findings) or f'<p class="muted">{e(L["none"])}</p>'
    parts.append(_section("findings", L["findings"], toolbar + cards, total))

    # ------------------------------------------------------ relacionamentos
    rel_html = ""
    for m in inv.get("models", []) or []:
        rows = [[e(r["from"]), e(r["to"]),
                 '<span class="ok">✓</span>' if r["is_active"] else '<span class="bad">inactive</span>',
                 ("⇄ " if str(r["cross_filter"]).lower() == "bothdirections" else "→ ") + e(r["cross_filter"]),
                 e(r["cardinality"])] for r in m.get("relationships", [])]
        rel_html += f"<h3>{e(m['name'])}</h3>" + _table([L["from"], L["to"], L["active"], L["cross"], L["card"]],
                                                       rows, raw=True)
    parts.append(_section("relationships", L["model_map"], _diagram(ins["model_graph"], L)
                          + (f"<details><summary><b>{e(L['relationships'])}</b></summary>{rel_html}</details>"
                             if rel_html else "")))

    # ------------------------------------------------------------------ DAX
    dax_html = ""
    for m in inv.get("models", []) or []:
        deep = sorted(m.get("measures", []), key=lambda x: -(x.get("depth") or 0))[:20]
        dax_html += _table([L["measure"], L["depth"], L["depends"]],
                           [[f"[{x['name']}]", str(x.get("depth")), ", ".join(x.get("measure_dependencies", []))]
                            for x in deep])
    parts.append(_section("dax", L["measures_t"], _measures(ins, L) or dax_html))

    # -------------------------------------------------------------- visuais
    dm = doc.get("dependency_map", []) or []
    bad = [d for d in dm if d.get("status") != "ok"]
    vis_html = _pages(ins, L) + f'<p class="muted">{len(dm)} {e(L["bindings"])}</p>'
    if bad:
        vis_html += f"<h3>{e(L['broken'])}</h3>" + _table(
            [L["page"], L["visual"], L["usage"], L["kind"], L["table"], L["field"], L["status"]],
            [[d["page"], d.get("visual_title") or d["visual"], d["usage"], d["kind"], d["table"], d["field"],
              f'{d["status"]}: {d.get("detail")}'] for d in bad])
    if dm:
        vis_html += (f"<details><summary><b>{e(L['full_map'])}</b></summary>" + _table(
            [L["page"], L["visual"], L["type"], L["usage"], L["kind"], L["table"], L["field"], L["status"]],
            [[d["page"], d.get("visual_title") or d["visual"], d["visual_type"], d["usage"], d["kind"], d["table"],
              d["field"], d["status"]] for d in dm[:2000]]) + "</details>")
    parts.append(_section("visuals", L["visuals"], vis_html))

    # ---------------------------------------------------------- desempenho
    perf = doc.get("performance")
    if perf and perf.get("visuals"):
        mx = max((v.get("total_ms") or 0) for v in perf["visuals"]) or 1
        perf_rows: list[str] = []
        for v in perf["visuals"]:
            segs = "".join(f'<i class="{c}" style="width:{100 * (v.get(k) or 0) / mx:.2f}%" title="{k}: '
                           f'{(v.get(k) or 0):.0f} ms"></i>' for k, c in (("dax_query_ms", "p-dax"),
                           ("direct_query_ms", "p-dq"), ("visual_display_ms", "p-vis"), ("other_ms", "p-oth")))
            perf_rows.append(f'<div class="perfrow"><span>{e(v.get("visual_title") or v.get("visual_id"))} '
                        f'<span class="muted">({e(v.get("visual_type"))})</span></span><div class="perfbar">{segs}'
                        f'</div><b>{(v.get("total_ms") or 0):.0f} ms</b></div>')
        legend = ('<div class="legend"><span><i class="dot p-dax"></i>DAX query</span><span><i class="dot p-dq"></i>'
                  'Direct query</span><span><i class="dot p-vis"></i>Visual display</span><span><i class="dot p-oth">'
                  '</i>Other</span></div>')
        warn = "".join(f"<li>{e(w)}</li>" for w in perf.get("warnings", []))
        parts.append(_section("performance", L["performance"], legend + "".join(perf_rows)
                              + (f"<ul class='muted'>{warn}</ul>" if warn else "")))
    else:
        parts.append(_section("performance", L["performance"], f'<p class="notice">{e(L["no_perf"])}</p>'))

    # ------------------------------------------------------------- impacto
    ci = doc.get("change_impact")
    if ci:
        chips = " · ".join(f"{e(k)}: <b>{e(v)}</b>" for k, v in ci.get("summary", {}).items())
        imp = "".join(
            f'<div class="hyp"><b>{e(i["change"])}</b><p>{e(i["message"])}</p>'
            + (f'<p class="muted">{e(L["dependents"])}: {e(", ".join(i["dependent_measures"]))}</p>'
               if i["dependent_measures"] else "")
            + ("<ul>" + "".join(f"<li>{e(x)}</li>" for x in i["affected_visuals"]) + "</ul>"
               if i["affected_visuals"] else "") + "</div>" for i in ci.get("impacts", []))
        parts.append(_section("impact", L["impact"], f"<p>{chips}</p><p class='notice'>{e(ci.get('note'))}</p>"
                              + _table([L["type"], L["object"], L["change"], L["details"]],
                                       [[c["object_type"], c["object"], c["change"], "; ".join(c["details"])]
                                        for c in ci.get("changes", [])]) + imp))
    else:
        parts.append(_section("impact", L["impact"], f'<p class="notice">{e(L["no_impact"])}</p>'))

    # ------------------------------------------------------------ hipóteses
    invs = doc.get("investigations", []) or []
    if invs:
        hy = ""
        for iv in invs:
            hy += (f"<h3>{e(iv.get('from_table'))} → {e(', '.join(iv.get('targets', [])))}"
                   + (f" · [{e(iv['measure'])}]" if iv.get("measure") else "") + "</h3>"
                   + f"<b>{e(L['det_evidence'])}</b><pre>{e(chr(10).join(iv.get('evidence', [])))}</pre>")
            for h in iv.get("hypotheses", []):
                steps = "".join(f"<li>{e(s)}</li>" for s in h.get("verification_steps", []))
                hy += (f'<div class="hyp"><b>#{e(h.get("rank"))}</b> <span class="conf {e(h["confidence"])}">'
                       f'{e(h["confidence"])} {e(L["conf"])}</span> <b>{e(h["hypothesis"])}</b>'
                       f'<p class="muted">{e(h["justification"])}</p><ol>{steps}</ol></div>')
        parts.append(_section("hypotheses", L["hypotheses"], hy, len(invs)))
    else:
        parts.append(_section("hypotheses", L["hypotheses"], f'<p class="notice">{e(L["no_hyp"])}</p>'))

    # --------------------------------------------------------------- ações
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM"):
            groups[(f["rule_id"], f["recommendation"])].append(f)
    acts = sorted(groups.items(), key=lambda kv: (min(SEV_ORDER.index(x["severity"]) for x in kv[1]), -len(kv[1])))
    act_html = "".join(
        f'<li>{_badge(min((x["severity"] for x in v), key=SEV_ORDER.index))} <code>{e(k[0])}</code> {e(k[1])} '
        f'<span class="muted">({e(L["applies"])} {len(v)} {e(L["items"])})</span></li>' for k, v in acts)
    parts.append(_section("actions", L["actions"], f'<ol class="actions">{act_html}</ol>' if act_html
                          else f'<p class="muted">{e(L["none"])}</p>'))

    # ----------------------------------------------------------- limitações
    lims = "".join(f"<li>{e(x)}</li>" for x in doc.get("limitations", []) or [])
    parts.append(_section("limitations", L["limitations"], f"<ul>{lims}</ul>"))

    # ----------------------------------------------------------- inventário
    inv_html = ""
    for r in inv.get("reports", []) or []:
        inv_html += f"<h3>{e(r['name'])} <span class='muted'>({e(r['format'])}, {e(r['support'])})</span></h3>"
        inv_html += _table([L["page"], L["visual"], L["type"], L["field"], "Limitations"],
                           [[p["display_name"], v["title"] or v["name"], v["type"], str(v["field_count"]),
                             "; ".join(v["limitations"])] for p in r["pages"] for v in p["visuals"]])
    for m in inv.get("models", []) or []:
        inv_html += f"<h3>{e(m['name'])} <span class='muted'>({e(m['format'])}, {e(m['support'])})</span></h3>"
        inv_html += _table([L["table"], "Role", "Columns", "Measures", "Data sources"],
                           [[t["name"], str(t["role"]), str(len(t["columns"])), str(len(t["measures"])),
                             ", ".join(t["data_sources"])] for t in m["tables"]])
    if ins["sources"]:
        inv_html = f"<h3>{e(L['sources'])}</h3>" + _table(["Connector", L["table"]], [[k, ", ".join(v)] for k, v in
                                                                                     ins["sources"].items()]) + inv_html
    parts.append(_section("inventory", L["inventory"], inv_html or f'<p class="muted">{e(L["none"])}</p>'))

    nav_ids = ["overview", "summary", "priorities", "rules", "findings", "relationships", "dax", "visuals", "performance",
               "impact", "hypotheses", "actions", "limitations", "inventory"]
    nav_label = {**{i: L[i] for i in nav_ids}, "relationships": L["model_map"], "dax": L["measures_t"],
                 "visuals": L["pages_t"]}
    nav = "".join(f'<a href="#{i}">{e(nav_label[i])}</a>' for i in nav_ids if f'id="{i}"' in "".join(parts))
    meta = [f"v{doc.get('version', '')}", f"{L['generated']}: {doc.get('generated_at') or '-'}", L["readonly"]]
    if scope.get("modules"):
        meta.append(", ".join(scope["modules"]))
    if scope.get("performance_log"):
        meta.append(f"log: {scope['performance_log']}")
    head = (f'<header class="top"><div class="row">{_LOGO}<div><h1>Power BI PBIP Forensics</h1>'
            f'<div class="sub">{e(L["title"])} · <b>{e(doc.get("project"))}</b></div></div></div>'
            f'<div class="meta">' + "".join(f"<span>{e(m)}</span>" for m in meta) + "</div></header>")
    return (f'<!doctype html><html lang="{e(lang)}"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width, initial-scale=1"><title>PBIP Forensics · {e(doc.get("project"))}</title>'
            f"<style>{_CSS}</style></head><body>{head}<nav class='tabs'>{nav}</nav><main>{''.join(parts)}</main>"
            f"<footer>{e(L['footer'])}</footer><script>{_JS}</script></body></html>")
