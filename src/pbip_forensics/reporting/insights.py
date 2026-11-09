"""Insights derivados do documento de auditoria (função pura do JSON produzido).

Gera, para públicos técnicos e não técnicos:
- notas de saúde por área (fórmula transparente e documentada, indicativa);
- resumo em linguagem simples (narrativa) e "ganhos rápidos" priorizados;
- grafo do modelo para o diagrama;
- estatísticas de medidas (complexidade, medidas centrais, pastas);
- panorama por página e por fonte de dados.

Nada aqui lê arquivos do projeto: tudo vem do documento (findings + inventário),
o que permite usar o mesmo cálculo no relatório combinado dos scripts.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any

SEV_WEIGHT = {"CRITICAL": 20.0, "HIGH": 8.0, "MEDIUM": 3.0, "LOW": 1.0, "INFO": 0.0}
STATUS_FACTOR = {"confirmed": 1.0, "potential": 0.5, "inconclusive": 0.25}
SCORE_SCALE = 40.0  # nota = 100 * exp(-penalidade / 40)

AREAS = [
    ("model", {"Relationships", "Model structure"}),
    ("dax", {"DAX", "DAX performance", "Filter context"}),
    ("visuals", {"Visual dependencies"}),
    ("performance", {"Performance"}),
    ("files", {"Parsing"}),
]

INS_LABELS = {
    "en": {
        "model": "Data model", "dax": "DAX measures", "visuals": "Report & visuals", "performance": "Performance",
        "files": "Project files", "good": "Good", "attention": "Needs attention", "critical": "Critical",
        "not_measured": "Not measured", "quick": "Quick win", "medium": "Medium effort", "structural": "Structural",
    },
    "pt-BR": {
        "model": "Modelo de dados", "dax": "Medidas DAX", "visuals": "Relatório e visuais",
        "performance": "Desempenho", "files": "Arquivos do projeto", "good": "Bom", "attention": "Requer atenção",
        "critical": "Crítico", "not_measured": "Não medido", "quick": "Ganho rápido", "medium": "Esforço médio",
        "structural": "Estrutural",
    },
}

# Título em linguagem simples, esforço típico e público de cada regra.
PLAIN: dict[str, tuple[str, str, str]] = {
    # regra: (esforço, en, pt)
    "VIS001": ("quick", "Fix visuals bound to tables that no longer exist",
               "Corrigir visuais ligados a tabelas que não existem mais"),
    "VIS002": ("quick", "Fix visuals bound to removed or renamed fields",
               "Corrigir visuais ligados a campos removidos ou renomeados"),
    "DAX001": ("quick", "Fix measures that reference missing objects",
               "Corrigir medidas que apontam para objetos inexistentes"),
    "DAX002": ("medium", "Break circular dependencies between measures", "Eliminar dependência circular entre medidas"),
    "DAX007": ("quick", "Fix USERELATIONSHIP/CROSSFILTER without a relationship",
               "Corrigir USERELATIONSHIP/CROSSFILTER sem relacionamento"),
    "DAX013": ("quick", "Fill in empty measures", "Preencher medidas vazias"),
    "MOD001": ("quick", "Fix relationships pointing to missing columns",
               "Corrigir relacionamentos com colunas inexistentes"),
    "MOD006": ("structural", "Remove ambiguous filter paths between tables",
               "Eliminar caminhos de filtro ambíguos entre tabelas"),
    "MOD003": ("medium", "Review bidirectional relationships", "Revisar relacionamentos bidirecionais"),
    "MOD004": ("structural", "Review many-to-many relationships", "Revisar relacionamentos muitos-para-muitos"),
    "MOD002": ("medium", "Review inactive relationships", "Revisar relacionamentos inativos"),
    "MOD007": ("quick", "Align data types of relationship keys", "Alinhar tipos de dados das chaves"),
    "MOD008": ("medium", "Connect or remove isolated tables", "Conectar ou remover tabelas isoladas"),
    "MOD009": ("quick", "Turn off Auto date/time and use a date table",
               "Desligar data/hora automática e usar tabela calendário"),
    "MOD010": ("quick", "Hide foreign-key columns on fact tables", "Ocultar chaves estrangeiras das tabelas fato"),
    "VIS005": ("medium", "Fix visuals whose grouping cannot filter the measure",
               "Corrigir visuais cujo agrupamento não filtra a medida"),
    "VIS006": ("medium", "Fix tables combining unrelated data", "Corrigir tabelas que combinam dados sem relação"),
    "VIS007": ("medium", "Review page filters that do not reach the measures",
               "Revisar filtros de página que não chegam às medidas"),
    "VIS008": ("medium", "Reduce the number of visuals on heavy pages", "Reduzir a quantidade de visuais por página"),
    "VIS003": ("medium", "Review visuals the tool could not interpret",
               "Revisar visuais que a ferramenta não conseguiu interpretar"),
    "DAX003": ("medium", "Replace FILTER over whole tables with column filters",
               "Trocar FILTER sobre tabela inteira por filtros de coluna"),
    "DAX004": ("medium", "Simplify nested iterators", "Simplificar iteradores aninhados"),
    "DAX005": ("medium", "Avoid measure calls per row of fact tables", "Evitar medidas por linha em tabelas fato"),
    "DAX009": ("quick", "Use DIVIDE instead of '/'", "Usar DIVIDE em vez de '/'"),
    "DAX010": ("quick", "Remove IFERROR/ISERROR", "Remover IFERROR/ISERROR"),
    "DAX011": ("quick", "Clean up unused measures", "Limpar medidas não utilizadas"),
    "DAX014": ("quick", "Set format strings on numeric measures", "Definir formato nas medidas numéricas"),
    "COL001": ("quick", "Remove unused columns to shrink the model", "Remover colunas sem uso para reduzir o modelo"),
    "PERF001": ("medium", "Speed up the slowest visuals", "Acelerar os visuais mais lentos"),
    "PRS001": ("quick", "Fix files that could not be read", "Corrigir arquivos que não puderam ser lidos"),
}
EFFORT_RANK = {"quick": 0, "medium": 1, "structural": 2}
_VALUE_INFO_RULES = {"DAX011", "COL001", "MOD009", "DAX014", "MOD010"}


def _grade(score: int | None) -> str:
    if score is None:
        return "not_measured"
    return "good" if score >= 85 else "attention" if score >= 65 else "critical"


def scores(findings: list[dict[str, Any]], has_perf: bool) -> dict[str, Any]:
    """Notas indicativas 0–100 por área: 100·exp(-Σ peso(severidade)·fator(status)/40)."""
    areas: list[dict[str, Any]] = []
    for key, cats in AREAS:
        fs = [f for f in findings if f.get("category") in cats]
        if key == "performance" and not has_perf:
            areas.append({"key": key, "score": None, "grade": "not_measured", "findings": len(fs)})
            continue
        penalty = sum(SEV_WEIGHT.get(f["severity"], 0) * STATUS_FACTOR.get(f["status"], 0.5) for f in fs)
        sc = round(100 * math.exp(-penalty / SCORE_SCALE))
        areas.append({"key": key, "score": sc, "grade": _grade(sc), "findings": len(fs),
                      "penalty": round(penalty, 1)})
    valid: list[int] = [a["score"] for a in areas if a["score"] is not None and a["key"] != "files"]
    overall = round(sum(valid) / len(valid)) if valid else None
    return {"overall": overall, "grade": _grade(overall), "areas": areas,
            "formula": "score = 100 × exp(−Σ weight(severity) × factor(status) / 40); weights CRITICAL 20, HIGH 8, "
                       "MEDIUM 3, LOW 1, INFO 0; factors confirmed 1, potential 0.5, inconclusive 0.25."}


def quick_wins(findings: list[dict[str, Any]], lang: str, limit: int = 8) -> list[dict[str, Any]]:
    """Ações agrupadas por regra, ordenadas por esforço e severidade."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        if f["severity"] != "INFO" or f["rule_id"] in _VALUE_INFO_RULES:
            groups[f["rule_id"]].append(f)
    sev_rank = {s: i for i, s in enumerate(SEV_WEIGHT)}
    out = []
    for rid, fs in groups.items():
        effort, en, pt = PLAIN.get(rid, ("medium", fs[0]["title"], fs[0]["title"]))
        worst = min((f["severity"] for f in fs), key=lambda s: sev_rank[s])
        out.append({"rule_id": rid, "title": pt if lang == "pt-BR" else en, "effort": effort, "severity": worst,
                    "count": len(fs), "confirmed": sum(1 for f in fs if f["status"] == "confirmed"),
                    "recommendation": fs[0]["recommendation"]})
    out.sort(key=lambda a: (sev_rank[a["severity"]] if a["severity"] in ("CRITICAL", "HIGH") else 5,
                            EFFORT_RANK[a["effort"]], sev_rank[a["severity"]], -a["count"]))
    return out[:limit]


def narrative(doc: dict[str, Any], lang: str) -> list[str]:
    """Resumo em linguagem simples, sem jargão, derivado apenas das evidências."""
    pt = lang == "pt-BR"
    fs = doc.get("findings", []) or []
    c = (doc.get("inventory") or {}).get("counts", {}) or {}
    by = Counter(f["rule_id"] for f in fs)
    conf = Counter(f["rule_id"] for f in fs if f["status"] == "confirmed")
    s: list[str] = []
    if c:
        s.append((f"O projeto tem {c.get('pages', 0)} páginas com {c.get('visuals', 0)} visuais, apoiadas em "
                  f"{c.get('tables', 0)} tabelas, {c.get('relationships', 0)} relacionamentos e "
                  f"{c.get('measures', 0)} medidas.") if pt else
                 (f"The project has {c.get('pages', 0)} pages with {c.get('visuals', 0)} visuals, built on "
                  f"{c.get('tables', 0)} tables, {c.get('relationships', 0)} relationships and "
                  f"{c.get('measures', 0)} measures."))
    broken = conf["VIS001"] + conf["VIS002"]
    if broken:
        s.append(f"{broken} vínculo(s) de visual usam campos que não existem mais: esses visuais exibem erro."
                 if pt else f"{broken} visual binding(s) use fields that no longer exist: those visuals show an error.")
    dax_err = conf["DAX001"] + conf["DAX002"] + conf["DAX007"] + conf["DAX013"]
    if dax_err:
        s.append(f"{dax_err} problema(s) confirmados em fórmulas DAX impedem medidas de calcular."
                 if pt else f"{dax_err} confirmed DAX formula problem(s) prevent measures from calculating.")
    if by["MOD006"]:
        s.append("Existem caminhos de filtro ambíguos entre tabelas: alguns números podem depender de qual caminho o "
                 "Power BI escolhe. É o principal ponto estrutural a revisar." if pt else
                 "There are ambiguous filter paths between tables: some numbers may depend on which path Power BI "
                 "uses. This is the main structural point to review.")
    filt = by["VIS005"] + by["VIS006"] + by["VIS007"]
    if filt:
        s.append(f"{filt} visual(is)/filtro(s) podem não filtrar como o usuário espera (ex.: linhas repetindo o total "
                 "ou dados sem relação)." if pt else
                 f"{filt} visual(s)/filter(s) may not filter as users expect (e.g., rows repeating the total or "
                 "unrelated data).")
    perf = doc.get("performance")
    slow = [f for f in fs if f["rule_id"] == "PERF001"]
    if perf and slow:
        s.append(f"No log de desempenho, {len(slow)} visual(is) passaram do limite de tempo; o mais lento foi "
                 f"“{slow[0]['title'].split(': ', 1)[-1]}”." if pt else
                 f"In the performance log, {len(slow)} visual(s) exceeded the time threshold; the slowest was "
                 f"“{slow[0]['title'].split(': ', 1)[-1]}”.")
    elif not perf:
        s.append("Não foi informado log do Performance Analyzer, então não há medição real de lentidão; existem "
                 f"{by['DAX003'] + by['DAX004'] + by['DAX005']} padrões DAX que merecem medição." if pt else
                 "No Performance Analyzer log was provided, so slowness was not measured; there are "
                 f"{by['DAX003'] + by['DAX004'] + by['DAX005']} DAX patterns worth measuring.")
    cleanup = by["DAX011"]
    cols = sum(int(f["title"].split("(")[-1].split(" ")[0]) for f in fs if f["rule_id"] == "COL001"
               and f["title"].split("(")[-1].split(" ")[0].isdigit())
    if cleanup or cols:
        s.append(f"Oportunidade de limpeza: {cleanup} medida(s) e {cols} coluna(s) sem uso detectado."
                 if pt else f"Clean-up opportunity: {cleanup} measure(s) and {cols} column(s) with no detected use.")
    if not broken and not dax_err and not by["MOD006"] and not filt:
        s.append("Nenhum problema estrutural grave foi encontrado nos arquivos." if pt else
                 "No serious structural problem was found in the files.")
    return s


def model_graph(doc: dict[str, Any]) -> dict[str, Any]:
    """Nós e arestas para o diagrama (tabelas automáticas de data são agrupadas)."""
    models = (doc.get("inventory") or {}).get("models", []) or []
    if not models:
        return {"nodes": [], "edges": [], "hidden_auto": 0}
    m = models[0]
    auto = [t for t in m["tables"] if t["name"].startswith(("LocalDateTable_", "DateTableTemplate_"))]
    nodes = [{"name": t["name"], "role": t.get("role") or "disconnected", "columns": len(t["columns"]),
              "measures": len(t["measures"]), "calculated": t.get("is_calculated", False)}
             for t in m["tables"] if t not in auto]
    names = {n["name"] for n in nodes}
    amb_ids: set[str] = set()
    for f in doc.get("findings", []) or []:
        if f["rule_id"] == "MOD006" and f["severity"] == "HIGH" and "/cycle/" in f.get("object_ref", ""):
            amb_ids |= set(f["object_ref"].split("/cycle/", 1)[1].split("+"))
    edges = []
    for r in m.get("relationships", []):
        ft, tt = r["from"].split("'[")[0].strip("'"), r["to"].split("'[")[0].strip("'")
        if ft in names and tt in names:
            edges.append({"id": r["id"], "from": ft, "to": tt, "active": r["is_active"],
                          "both": str(r["cross_filter"]).lower() == "bothdirections", "card": r["cardinality"],
                          "ambiguous": r["id"] in amb_ids, "label": f"{r['from']} → {r['to']}"})
    return {"nodes": nodes, "edges": edges, "hidden_auto": len(auto), "model": m["name"]}


def measure_stats(doc: dict[str, Any]) -> dict[str, Any]:
    models = (doc.get("inventory") or {}).get("models", []) or []
    measures = [x for m in models for x in m.get("measures", [])]
    used_in_visuals = Counter(d["field"] for d in doc.get("dependency_map", []) or [] if d.get("kind") == "measure")
    referenced = Counter(dep for x in measures for dep in x.get("measure_dependencies", []))
    complex_top = sorted((x for x in measures if x.get("complexity")),
                         key=lambda x: -x["complexity"]["score"])[:10]
    hubs = sorted(measures, key=lambda x: -(referenced[x["name"]] * 2 + used_in_visuals[x["name"]]))[:10]
    folders = Counter((x.get("display_folder") or "—") for x in measures)
    return {
        "total": len(measures),
        "no_format": sum(1 for x in measures if not x.get("format_string")),
        "no_folder": sum(1 for x in measures if not x.get("display_folder")),
        "max_depth": max((x.get("depth") or 0 for x in measures), default=0),
        "complex": [{"name": x["name"], "table": x["table"], **x["complexity"], "depth": x.get("depth"),
                     "used_by_measures": referenced[x["name"]], "used_in_visuals": used_in_visuals[x["name"]]}
                    for x in complex_top],
        "hubs": [{"name": x["name"], "used_by_measures": referenced[x["name"]],
                  "used_in_visuals": used_in_visuals[x["name"]]} for x in hubs
                 if referenced[x["name"]] or used_in_visuals[x["name"]]],
        "folders": folders.most_common(12),
    }


def page_stats(doc: dict[str, Any]) -> list[dict[str, Any]]:
    reports = (doc.get("inventory") or {}).get("reports", []) or []
    dm = doc.get("dependency_map", []) or []
    fs = doc.get("findings", []) or []
    out = []
    for r in reports:
        for p in r.get("pages", []):
            vis = p.get("visuals", [])
            pdm = [d for d in dm if d.get("page") == p["display_name"] and d.get("report", r["name"]) == r["name"]]
            sev = Counter(f["severity"] for f in fs if p.get("path") and str(f.get("path", "")).startswith(p["path"]))
            out.append({
                "report": r["name"], "page": p["display_name"], "visuals": len(vis),
                "data_visuals": sum(1 for v in vis if v.get("field_count")),
                "slicers": sum(1 for v in vis if "slicer" in str(v.get("type", "")).lower()),
                "custom": sum(1 for v in vis if v.get("is_custom")),
                "filters": len(p.get("page_filters", [])) + sum(v.get("visual_filters", 0) for v in vis),
                "measures": len({d["field"] for d in pdm if d.get("kind") == "measure"}),
                "tables": sorted({d["table"] for d in pdm if d.get("table") and d.get("kind") != "measure"}),
                "broken": sum(1 for d in pdm if d.get("status") not in ("ok", "unknown")),
                "findings": dict(sev),
            })
    return out


def data_sources(doc: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for m in (doc.get("inventory") or {}).get("models", []) or []:
        for t in m.get("tables", []):
            for s in t.get("data_sources", []):
                out[s].append(t["name"])
    return dict(out)


def compute_insights(doc: dict[str, Any], lang: str = "en") -> dict[str, Any]:
    fs = doc.get("findings", []) or []
    labels = INS_LABELS.get(lang, INS_LABELS["en"])
    sc = scores(fs, bool(doc.get("performance")))
    for a in sc["areas"]:
        a["label"] = labels[a["key"]]
        a["grade_label"] = labels[a["grade"]]
    sc["grade_label"] = labels[sc["grade"]]
    wins = quick_wins(fs, lang)
    for w in wins:
        w["effort_label"] = labels[w["effort"]]
    return {"scores": sc, "narrative": narrative(doc, lang), "quick_wins": wins, "model_graph": model_graph(doc),
            "measures": measure_stats(doc), "pages": page_stats(doc), "sources": data_sources(doc)}
