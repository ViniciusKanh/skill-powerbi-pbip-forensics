"""Parser de relatórios Power BI (*.Report): PBIR (pasta definition/) e PBIR-Legacy.

Referências:
- https://learn.microsoft.com/power-bi/developer/projects/projects-report
- Esquemas públicos: visualContainer 2.x, visualConfiguration 2.x, semanticQuery 1.x
  (https://developer.microsoft.com/json-schemas/fabric/item/report/definition/...)

PBIR moderno: definition/version.json, report.json, pages/pages.json,
pages/<p>/page.json e pages/<p>/visuals/<v>/visual.json.
PBIR-Legacy: report.json único na raiz da pasta do relatório; o esquema NÃO é
documentado publicamente, portanto o suporte é "limited" (melhor esforço).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pbip_forensics.models import FieldRef, ForensicsError, Page, ParseIssue, Report, Visual
from pbip_forensics.security.safety import DEFAULT_MAX_FILE_BYTES, is_within, read_json, rel

# Tipos de visual nativos conhecidos (visualType). Outros tipos são tratados como
# customizados ou não reconhecidos — nunca como erro.
BUILTIN_VISUALS = {
    "card", "cardVisual", "multiRowCard", "tableEx", "pivotTable", "slicer", "advancedSlicerVisual",
    "listSlicer", "textSlicer", "columnChart", "barChart", "clusteredColumnChart", "clusteredBarChart",
    "hundredPercentStackedColumnChart", "hundredPercentStackedBarChart", "lineChart", "areaChart",
    "stackedAreaChart", "hundredPercentStackedAreaChart", "lineClusteredColumnComboChart",
    "lineStackedColumnComboChart", "ribbonChart", "waterfallChart", "funnel", "scatterChart",
    "pieChart", "donutChart", "treemap", "map", "filledMap", "shapeMap", "azureMap", "gauge", "kpi",
    "textbox", "image", "shape", "basicShape", "actionButton", "pageNavigator", "bookmarkNavigator",
    "decompositionTreeVisual", "keyDriversVisual", "qnaVisual", "scriptVisual", "pythonVisual",
    "rdlVisual", "scorecard", "aiNarratives", "esriVisual", "paginator", "group", "matrix", "table",
}
# Visuais sem vínculo de dados por natureza (não geram limitação).
NO_DATA_VISUALS = {"textbox", "image", "shape", "basicShape", "actionButton", "pageNavigator",
                   "bookmarkNavigator", "group", "paginator"}
AGG_FUNCTIONS = {0: "Sum", 1: "Average", 2: "DistinctCount", 3: "Min", 4: "Max", 5: "Count",
                 6: "Median", 7: "StandardDeviation", 8: "Variance"}


def _entity(expr: Any, aliases: dict[str, str]) -> str | None:
    """Resolve a entidade (tabela) de um SourceRef/PropertyVariationSource."""
    if not isinstance(expr, dict):
        return None
    src = expr.get("SourceRef")
    if isinstance(src, dict):
        ent = src.get("Entity")
        if ent:
            return str(ent)
        alias = src.get("Source")
        return aliases.get(str(alias)) if alias is not None else None
    pvs = expr.get("PropertyVariationSource")
    if isinstance(pvs, dict):
        return _entity(pvs.get("Expression"), aliases)
    return None


def field_from_container(c: Any, aliases: dict[str, str] | None = None, role: str = "",
                         usage: str = "projection") -> FieldRef | None:
    """Converte um QueryExpressionContainer (semanticQuery) em FieldRef."""
    aliases = aliases or {}
    if not isinstance(c, dict):
        return None
    if "Column" in c and isinstance(c["Column"], dict):
        col = c["Column"]
        return FieldRef("column", _entity(col.get("Expression"), aliases), col.get("Property"), role, usage)
    if "Measure" in c and isinstance(c["Measure"], dict):
        mea = c["Measure"]
        return FieldRef("measure", _entity(mea.get("Expression"), aliases), mea.get("Property"), role, usage)
    if "Aggregation" in c and isinstance(c["Aggregation"], dict):
        agg = c["Aggregation"]
        inner = field_from_container(agg.get("Expression"), aliases, role, usage)
        if inner is None:
            return FieldRef("unknown", None, None, role, usage, "Aggregation over unsupported expression")
        inner.kind = "aggregation"
        fn = agg.get("Function")
        inner.detail = AGG_FUNCTIONS.get(fn, str(fn)) if isinstance(fn, int) else str(fn)
        return inner
    if "HierarchyLevel" in c and isinstance(c["HierarchyLevel"], dict):
        hl = c["HierarchyLevel"]
        hier = (hl.get("Expression") or {}).get("Hierarchy") or {}
        hexpr = hier.get("Expression") or {}
        pvs = hexpr.get("PropertyVariationSource") if isinstance(hexpr, dict) else None
        if isinstance(pvs, dict):
            # Hierarquia automática de data: aponta para a coluna de data base.
            return FieldRef("column", _entity(pvs.get("Expression"), aliases), pvs.get("Property"),
                            role, usage, f"auto date hierarchy level {hl.get('Level')}")
        return FieldRef("hierarchyLevel", _entity(hexpr, aliases), hier.get("Hierarchy"), role, usage,
                        f"level {hl.get('Level')}")
    if "NativeVisualCalculation" in c:
        return FieldRef("visualCalculation", None, (c["NativeVisualCalculation"] or {}).get("Name"),
                        role, usage, "visual calculation (evaluated in visual)")
    keys = ", ".join(sorted(k for k in c if k not in ("Name", "NativeReferenceName", "Annotations")))
    return FieldRef("unknown", None, None, role, usage, f"Unsupported expression: {keys[:60]}")


def _filters(cfg: Any, aliases: dict[str, str] | None = None) -> list[FieldRef]:
    out: list[FieldRef] = []
    filters = cfg.get("filters", []) if isinstance(cfg, dict) else []
    for flt in filters or []:
        if isinstance(flt, dict):
            fr = field_from_container(flt.get("field"), aliases, flt.get("type", ""), "filter")
            if fr is not None:
                out.append(fr)
    return out


def _title(visual: dict[str, Any]) -> str | None:
    """Extrai o título literal do visual, quando definido."""
    try:
        val = visual["visualContainerObjects"]["title"][0]["properties"]["text"]["expr"]["Literal"]["Value"]
    except (KeyError, IndexError, TypeError):
        return None
    val = str(val)
    return val[1:-1].replace("''", "'") if len(val) >= 2 and val[0] == "'" == val[-1] else val


def parse_visual_json(data: Any, page: str, path: str) -> Visual:
    """Interpreta um visual.json PBIR (visualContainer)."""
    if not isinstance(data, dict):
        return Visual(name=Path(path).parent.name, page=page, visual_type="unparsed", path=path,
                      limitations=["visual.json root is not an object"])
    name = str(data.get("name") or Path(path).parent.name)
    if "visualGroup" in data:
        return Visual(name=name, page=page, visual_type="group", path=path, is_group=True,
                      title=(data.get("visualGroup") or {}).get("displayName"))
    vis = data.get("visual") or {}
    vtype = str(vis.get("visualType") or "unknown")
    v = Visual(name=name, page=page, visual_type=vtype, path=path, title=_title(vis))
    v.is_custom = vtype not in BUILTIN_VISUALS
    query = vis.get("query") or {}
    for role, state in (query.get("queryState") or {}).items():
        for proj in (state or {}).get("projections", []) or []:
            fr = field_from_container((proj or {}).get("field"), None, role, "projection")
            if fr is not None:
                v.fields.append(fr)
    for srt in (query.get("sortDefinition") or {}).get("sort", []) or []:
        fr = field_from_container((srt or {}).get("field"), None, "sort", "sort")
        if fr is not None:
            v.fields.append(fr)
    vfilters = _filters(data.get("filterConfig"))
    v.filter_count = len(vfilters)
    v.fields.extend(vfilters)
    if any(f.kind == "unknown" for f in v.fields):
        v.limitations.append("Some field expressions use unsupported query constructs")
    if v.is_custom and not v.fields:
        v.limitations.append(f"Custom or unrecognized visual '{vtype}': data bindings not interpretable")
    return v


def _parse_legacy(root: Path, report: Report, data: dict[str, Any]) -> None:
    """Extração de melhor esforço do PBIR-Legacy (esquema não documentado)."""
    report.support = "limited"
    report.issues.append(ParseIssue(report.path, "PBIR-Legacy report.json: undocumented schema, "
                                    "best-effort extraction only", kind="limited-support"))
    for sec in data.get("sections", []) or []:
        if not isinstance(sec, dict):
            continue
        pname = str(sec.get("name", ""))
        page = Page(name=pname, display_name=str(sec.get("displayName", pname)), path=report.path)
        for vc in sec.get("visualContainers", []) or []:
            try:
                cfg = json.loads(vc.get("config", "{}")) if isinstance(vc, dict) else {}
            except (json.JSONDecodeError, TypeError):
                cfg = {}
            single = cfg.get("singleVisual") or {}
            pq = single.get("prototypeQuery") or {}
            aliases = {str(f.get("Name")): str(f.get("Entity")) for f in pq.get("From", []) or []
                       if isinstance(f, dict)}
            vis = Visual(name=str(cfg.get("name", "")), page=pname,
                         visual_type=str(single.get("visualType", "unknown")), path=report.path)
            vis.is_custom = vis.visual_type not in BUILTIN_VISUALS
            for sel in pq.get("Select", []) or []:
                fr = field_from_container(sel, aliases)
                if fr is not None:
                    vis.fields.append(fr)
            vis.limitations.append("PBIR-Legacy: visual-level filters and formatting not analyzed")
            page.visuals.append(vis)
        report.pages.append(page)


def load_report(root: Path, folder: Path, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> Report:
    """Carrega um diretório *.Report (somente leitura)."""
    name = folder.name[: -len(".Report")] if folder.name.endswith(".Report") else folder.name
    report = Report(name=name, path=rel(root, folder))

    def safe_json(p: Path) -> Any:
        try:
            return read_json(root, p, max_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError, ForensicsError) as exc:
            report.issues.append(ParseIssue(rel(root, p), f"Malformed or unreadable JSON: {exc}"))
            return None

    pbir = folder / "definition.pbir"
    if pbir.is_file():
        meta = safe_json(pbir)
        if isinstance(meta, dict):
            report.pbir_version = str(meta.get("version")) if meta.get("version") is not None else None
            dref = meta.get("datasetReference") or {}
            if isinstance(dref.get("byPath"), dict):
                rpath = str(dref["byPath"].get("path", ""))
                report.dataset_ref = rpath
                target = (folder / rpath).resolve()
                if is_within(root, target) and target.is_dir():
                    report.model_path = rel(root, target)
                else:
                    report.issues.append(ParseIssue(rel(root, pbir), "datasetReference.byPath target not "
                                                    "found inside the authorized scope", kind="structure"))
            elif "byConnection" in dref:
                report.dataset_ref = "byConnection"  # string de conexão nunca é copiada
    else:
        report.issues.append(ParseIssue(report.path, "definition.pbir not found", kind="structure"))

    definition = folder / "definition"
    legacy = folder / "report.json"
    if definition.is_dir():
        report.format = "pbir"
        rep = safe_json(definition / "report.json") if (definition / "report.json").is_file() else None
        if rep is None and not (definition / "report.json").is_file():
            report.issues.append(ParseIssue(rel(root, definition), "definition/report.json missing",
                                            kind="structure"))
        if isinstance(rep, dict):
            report.filters = _filters(rep.get("filterConfig"))
            report.custom_visual_ids = [str(x) for x in rep.get("publicCustomVisuals", []) or []]
        ext_path = definition / "reportExtensions.json"
        if ext_path.is_file():
            ext = safe_json(ext_path)
            for ent in (ext or {}).get("entities", []) if isinstance(ext, dict) else []:
                for m in (ent or {}).get("measures", []) or []:
                    report.extension_measures.append(f"{ent.get('name')}[{m.get('name')}]")
        pages_dir = definition / "pages"
        order: list[str] = []
        if (pages_dir / "pages.json").is_file():
            pj = safe_json(pages_dir / "pages.json")
            if isinstance(pj, dict):
                order = [str(x) for x in pj.get("pageOrder", []) or []]
        page_dirs = sorted([d for d in pages_dir.iterdir() if d.is_dir() and not d.is_symlink()]
                           if pages_dir.is_dir() else [],
                           key=lambda d: (order.index(d.name) if d.name in order else len(order), d.name))
        for pdir in page_dirs:
            pdata = safe_json(pdir / "page.json") if (pdir / "page.json").is_file() else None
            pname = str((pdata or {}).get("name", pdir.name)) if isinstance(pdata, dict) else pdir.name
            disp = str(pdata.get("displayName", pname)) if isinstance(pdata, dict) else pname
            page = Page(name=pname, display_name=disp, path=rel(root, pdir))
            if isinstance(pdata, dict):
                page.filters = _filters(pdata.get("filterConfig"))
            vdir = pdir / "visuals"
            for vd in sorted(vdir.iterdir()) if vdir.is_dir() else []:
                vj = vd / "visual.json"
                if not vd.is_dir() or vd.is_symlink() or not vj.is_file():
                    continue
                vdata = safe_json(vj)
                if vdata is None:
                    page.visuals.append(Visual(name=vd.name, page=pname, visual_type="unparsed",
                                               path=rel(root, vj),
                                               limitations=["visual.json is malformed; not analyzed"]))
                    continue
                page.visuals.append(parse_visual_json(vdata, pname, rel(root, vj)))
            report.pages.append(page)
    elif legacy.is_file():
        report.format = "pbir-legacy"
        data = safe_json(legacy)
        if isinstance(data, dict):
            _parse_legacy(root, report, data)
        else:
            report.support = "unsupported"
    else:
        report.support = "unsupported"
        report.issues.append(ParseIssue(report.path, "No definition/ (PBIR) or report.json (PBIR-Legacy)",
                                        kind="structure"))
    if any(i.kind == "parse-error" for i in report.issues) and report.support == "full":
        report.support = "limited"
    return report
