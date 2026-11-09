"""Comparação entre duas versões de um projeto PBIP (Módulo 7).

Classifica alterações (added/removed/modified) e calcula o impacto potencial
(medidas dependentes, visuais e páginas). Uma alteração textual NUNCA é
apresentada como regressão comprovada: o resultado indica necessidade de teste.
"""

from __future__ import annotations

from typing import Any

from pbip_forensics.analyzers.semantic import SemanticIndex
from pbip_forensics.models import Project, Relationship, SemanticModel
from pbip_forensics.parsers.dax import normalized_tokens


def _rel_key(r: Relationship) -> str:
    return f"'{r.from_table}'[{r.from_column}] -> '{r.to_table}'[{r.to_column}]"


def _rel_props(r: Relationship) -> dict[str, Any]:
    return {"isActive": r.is_active, "crossFilteringBehavior": r.cross_filter,
            "fromCardinality": r.from_cardinality, "toCardinality": r.to_cardinality}


def _models(project: Project) -> dict[str, SemanticModel]:
    return {m.name: m for m in project.models}


def _change(kind: str, obj: str, change: str, details: list[str] | None = None) -> dict[str, Any]:
    return {"object_type": kind, "object": obj, "change": change, "details": details or []}


def _diff_model(before: SemanticModel, after: SemanticModel) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    bt = {t.name.lower(): t for t in before.tables}
    at = {t.name.lower(): t for t in after.tables}
    for k in sorted(set(bt) | set(at)):
        if k not in at:
            out.append(_change("table", bt[k].name, "removed"))
            continue
        if k not in bt:
            out.append(_change("table", at[k].name, "added"))
            continue
        tb, ta = bt[k], at[k]
        bc = {c.name.lower(): c for c in tb.columns}
        ac = {c.name.lower(): c for c in ta.columns}
        for c in sorted(set(bc) | set(ac)):
            name = f"'{ta.name}'[{(ac.get(c) or bc[c]).name}]"
            if c not in ac:
                out.append(_change("column", name, "removed"))
            elif c not in bc:
                out.append(_change("column", name, "added"))
            else:
                det = []
                if bc[c].data_type != ac[c].data_type:
                    det.append(f"dataType: {bc[c].data_type} -> {ac[c].data_type}")
                if normalized_tokens(bc[c].expression or "") != normalized_tokens(ac[c].expression or ""):
                    det.append("calculated column expression changed")
                if bc[c].is_hidden != ac[c].is_hidden:
                    det.append(f"isHidden: {bc[c].is_hidden} -> {ac[c].is_hidden}")
                if det:
                    out.append(_change("column", name, "modified", det))
        bm = {m.name.lower(): m for m in tb.measures}
        am = {m.name.lower(): m for m in ta.measures}
        for m in sorted(set(bm) | set(am)):
            name = (am.get(m) or bm[m]).name
            if m not in am:
                out.append(_change("measure", name, "removed"))
            elif m not in bm:
                out.append(_change("measure", name, "added"))
            else:
                same_tokens = normalized_tokens(bm[m].expression) == normalized_tokens(am[m].expression)
                if not same_tokens:
                    out.append(_change("measure", name, "modified", ["DAX expression changed (token-level)"]))
                elif bm[m].expression.strip() != am[m].expression.strip():
                    out.append(_change("measure", name, "modified-formatting",
                                       ["Whitespace/comment-only change; tokens identical"]))
                if bm[m].format_string != am[m].format_string:
                    out.append(_change("measure", name, "modified",
                                       [f"formatString: {bm[m].format_string} -> {am[m].format_string}"]))
    br = {_rel_key(r): r for r in before.relationships}
    ar = {_rel_key(r): r for r in after.relationships}
    for k in sorted(set(br) | set(ar)):
        if k not in ar:
            out.append(_change("relationship", k, "removed"))
        elif k not in br:
            out.append(_change("relationship", k, "added"))
        else:
            pb, pa = _rel_props(br[k]), _rel_props(ar[k])
            det = [f"{p}: {pb[p]} -> {pa[p]}" for p in pb if pb[p] != pa[p]]
            if det:
                out.append(_change("relationship", k, "modified", det))
    return out


def _visual_index(project: Project) -> dict[str, Any]:
    vis = {}
    for rep in project.reports:
        for page in rep.pages:
            for v in page.visuals:
                vis[f"{rep.name}/{page.name}/{v.name}"] = (rep, page, v)
    return vis


def _diff_reports(before: Project, after: Project) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    bp = {f"{r.name}/{p.name}": p for r in before.reports for p in r.pages}
    ap = {f"{r.name}/{p.name}": p for r in after.reports for p in r.pages}
    for k in sorted(set(bp) | set(ap)):
        if k not in ap:
            out.append(_change("page", f"{k} ({bp[k].display_name})", "removed"))
        elif k not in bp:
            out.append(_change("page", f"{k} ({ap[k].display_name})", "added"))
        elif bp[k].display_name != ap[k].display_name:
            out.append(_change("page", k, "modified", [f"displayName: {bp[k].display_name} -> {ap[k].display_name}"]))
    bv, av = _visual_index(before), _visual_index(after)
    for k in sorted(set(bv) | set(av)):
        if k not in av:
            out.append(_change("visual", k, "removed"))
        elif k not in bv:
            out.append(_change("visual", k, "added"))
        else:
            vb, va = bv[k][2], av[k][2]
            det = []
            if vb.visual_type != va.visual_type:
                det.append(f"visualType: {vb.visual_type} -> {va.visual_type}")
            fb = sorted(f"{f.usage}:{f.kind}:{f.key()}" for f in vb.fields)
            fa = sorted(f"{f.usage}:{f.kind}:{f.key()}" for f in va.fields)
            if fb != fa:
                removed, added = sorted(set(fb) - set(fa)), sorted(set(fa) - set(fb))
                det.append("fields: -" + ", ".join(removed) + " +" + ", ".join(added))
            if det:
                out.append(_change("visual", k, "modified", det))
    return out


def _visuals_using(project: Project, predicate: Any) -> list[str]:
    hits = []
    for rep in project.reports:
        for page in rep.pages:
            for v in page.visuals:
                if any(predicate(f) for f in v.fields):
                    hits.append(f"{rep.name} / {page.display_name} / {v.title or v.name} ({v.visual_type})")
    return sorted(set(hits))


def diff_projects(before: Project, after: Project) -> dict[str, Any]:
    """Compara versões e produz análise de impacto (necessidade de teste)."""
    changes: list[dict[str, Any]] = []
    bm, am = _models(before), _models(after)
    for name in sorted(set(bm) | set(am)):
        if name not in am:
            changes.append(_change("model", name, "removed"))
        elif name not in bm:
            changes.append(_change("model", name, "added"))
        else:
            changes.extend(_diff_model(bm[name], am[name]))
    changes.extend(_diff_reports(before, after))
    impacts: list[dict[str, Any]] = []
    for model in [*am.values(), *[m for n, m in bm.items() if n not in am]]:
        idx = SemanticIndex(model)
        old_idx = SemanticIndex(bm[model.name]) if model.name in bm else idx
        for ch in changes:
            if ch["change"] == "modified-formatting":
                continue
            if ch["object_type"] == "measure":
                name = ch["object"]
                use_idx = idx if name.lower() in idx.measures else old_idx
                deps = use_idx.dependents(name)
                names = {name.lower(), *[d.lower() for d in deps]}
                visuals = _visuals_using(
                    after, lambda f, n=names: f.kind == "measure" and (f.property or "").lower() in n)
                if ch["change"] == "removed":
                    msg = (f"Measure '{name}' was removed. "
                           + ("It is still referenced by visuals in the current version: these bindings are "
                              "broken (confirmed)." if visuals else "No visual in the current version references it."))
                else:
                    msg = f"Measure '{name}' {ch['change']}. Visuals referencing it (directly or via dependent " \
                          f"measures) may require regression testing."
                impacts.append({"change": f"measure {name} ({ch['change']})", "message": msg,
                                "dependent_measures": deps, "affected_visuals": visuals})
            elif ch["object_type"] == "column" and ch["change"] in ("removed", "modified"):
                obj = ch["object"]
                tname, cname = obj[1:obj.index("']")], obj[obj.index("[") + 1:-1]
                users = sorted({ea.name for ea in [*idx.analyses.values(), *old_idx.analyses.values()]
                                if (tname, cname) in ea.column_refs}, key=str.lower)
                tl, cl = tname.lower(), cname.lower()
                visuals = _visuals_using(after, lambda f, t=tl, c=cl:
                                         (f.entity or "").lower() == t and (f.property or "").lower() == c)
                impacts.append({"change": f"column {obj} ({ch['change']})",
                                "message": f"Column {obj} {ch['change']}. Measures and visuals using it may "
                                           "require regression testing.",
                                "dependent_measures": users, "affected_visuals": visuals})
            elif ch["object_type"] == "relationship":
                left = ch["object"].split(" -> ")
                tables = {x.split("'")[1].lower() for x in left if "'" in x}
                measures = sorted({ea.name for ea in idx.analyses.values()
                                   if {t.lower() for t in idx.base_tables(ea.name)} & tables}, key=str.lower)
                mset = {m.lower() for m in measures}
                visuals = _visuals_using(after, lambda f, ts=tables, ms=mset: (f.entity or "").lower() in ts or
                                         (f.kind == "measure" and (f.property or "").lower() in ms))
                impacts.append({"change": f"relationship {ch['object']} ({ch['change']})",
                                "message": "Relationship change alters filter propagation between "
                                           f"{', '.join(sorted(tables))}. Measures aggregating these tables and "
                                           "visuals using them may require regression testing.",
                                "dependent_measures": measures, "affected_visuals": visuals})
        break  # um modelo por projeto é o caso suportado nesta versão
    summary = {c: sum(1 for x in changes if x["change"] == c)
               for c in ("added", "removed", "modified", "modified-formatting")}
    return {"type": "change-impact", "summary": summary, "changes": changes, "impacts": impacts,
            "note": "Textual/structural changes indicate where to test; they are not proof of a functional regression."}
