"""Utilitários para gerar projetos PBIP sintéticos (TMDL + PBIR) em disco.

Usado por tools/make_fixtures.py. Todos os dados são fictícios.
Estruturas seguem os esquemas públicos verificados (pbipProperties 1.0.0,
definitionProperties 2.0.0, semanticModel definitionProperties 1.0.0,
versionMetadata 1.0.0, pagesMetadata 1.0.0, page 2.0.0, visualContainer 2.4.0,
visualConfiguration 2.2.0, semanticQuery 1.3.0, filterConfiguration 1.2.0).
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any

SCHEMA = "https://developer.microsoft.com/json-schemas/fabric"
S_PBIP = f"{SCHEMA}/pbip/pbipProperties/1.0.0/schema.json"
S_PBIR = f"{SCHEMA}/item/report/definitionProperties/2.0.0/schema.json"
S_PBISM = f"{SCHEMA}/item/semanticModel/definitionProperties/1.0.0/schema.json"
S_VERSION = f"{SCHEMA}/item/report/definition/versionMetadata/1.0.0/schema.json"
S_REPORT = f"{SCHEMA}/item/report/definition/report/1.0.0/schema.json"
S_PAGES = f"{SCHEMA}/item/report/definition/pagesMetadata/1.0.0/schema.json"
S_PAGE = f"{SCHEMA}/item/report/definition/page/2.0.0/schema.json"
S_VISUAL = f"{SCHEMA}/item/report/definition/visualContainer/2.4.0/schema.json"


def tabs(text: str) -> str:
    """Converte indentação de 4 espaços (legível no código) em TABs (TMDL)."""
    out = []
    for line in textwrap.dedent(text).strip("\n").split("\n"):
        stripped = line.lstrip(" ")
        n = (len(line) - len(stripped)) // 4
        out.append("\t" * n + stripped)
    return "\n".join(out) + "\n"


def write(path: Path, content: str | dict[str, Any] | list[Any], crlf: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not isinstance(content, str):
        content = json.dumps(content, indent=2, ensure_ascii=False) + "\n"
    if crlf:
        content = content.replace("\n", "\r\n")
    path.write_bytes(content.encode("utf-8"))


def col(entity: str, prop: str) -> dict[str, Any]:
    return {"Column": {"Expression": {"SourceRef": {"Entity": entity}}, "Property": prop}}


def mea(entity: str, prop: str) -> dict[str, Any]:
    return {"Measure": {"Expression": {"SourceRef": {"Entity": entity}}, "Property": prop}}


def agg(entity: str, prop: str, fn: int = 0) -> dict[str, Any]:
    return {"Aggregation": {"Expression": col(entity, prop), "Function": fn}}


def visual(name: str, vtype: str, roles: dict[str, list[dict[str, Any]]] | None = None,
           title: str | None = None, filters: list[dict[str, Any]] | None = None, x: int = 0) -> dict[str, Any]:
    vis: dict[str, Any] = {"$schema": f"{SCHEMA}/item/report/definition/visualConfiguration/2.2.0/schema.json",
                           "visualType": vtype}
    if roles:
        qs = {}
        for role, fields in roles.items():
            projs = []
            for i, f in enumerate(fields):
                key = next(iter(f))
                inner = f[key]
                if key == "Aggregation":
                    inner = inner["Expression"]["Column"]
                ent = inner["Expression"]["SourceRef"]["Entity"]
                projs.append({"field": f, "queryRef": f"{ent}.{inner['Property']}.{role}{i}",
                              "nativeQueryRef": inner["Property"]})
            qs[role] = {"projections": projs}
        vis["query"] = {"queryState": qs}
    if title:
        vis["visualContainerObjects"] = {"title": [{"properties": {
            "text": {"expr": {"Literal": {"Value": "'" + title.replace("'", "''") + "'"}}}}}]}
    data: dict[str, Any] = {"$schema": S_VISUAL, "name": name,
                            "position": {"x": x, "y": 0, "z": 0, "width": 300, "height": 200}, "visual": vis}
    if filters:
        data["filterConfig"] = {"filters": filters}
    return data


def flt(name: str, field: dict[str, Any], ftype: str = "Categorical") -> dict[str, Any]:
    return {"name": name, "field": field, "type": ftype, "howCreated": "User"}


def write_model(root: Path, name: str, tables: dict[str, str], relationships: str = "",
                extra: dict[str, str] | None = None) -> Path:
    """Grava <name>.SemanticModel em TMDL (um arquivo por tabela)."""
    sm = root / f"{name}.SemanticModel"
    write(sm / "definition.pbism", {"$schema": S_PBISM, "version": "4.2", "settings": {}})
    write(sm / "definition" / "database.tmdl", tabs("""
        database
            compatibilityLevel: 1601
    """))
    refs = "\n".join(f"ref table {_q(t)}" for t in tables)
    write(sm / "definition" / "model.tmdl", tabs("""
        model Model
            culture: en-US
            defaultPowerBIDataSourceVersion: powerBI_V3

    """) + refs + "\n")
    for tname, body in tables.items():
        safe = "".join(ch if ch.isalnum() or ch in " _-" else "_" for ch in tname)
        write(sm / "definition" / "tables" / f"{safe}.tmdl", tabs(body))
    if relationships:
        write(sm / "definition" / "relationships.tmdl", tabs(relationships))
    for rel_path, content in (extra or {}).items():
        write(sm / rel_path, content)
    return sm


def _q(name: str) -> str:
    if any(ch in name for ch in " .=:'") or not name.isascii():
        return "'" + name.replace("'", "''") + "'"
    return name


def write_report(root: Path, name: str, model_name: str | None, pages: list[dict[str, Any]],
                 report_filters: list[dict[str, Any]] | None = None, by_path: str | None = None,
                 extra: dict[str, Any] | None = None) -> Path:
    """Grava <name>.Report em PBIR (definition/)."""
    rp = root / f"{name}.Report"
    dref: dict[str, Any]
    if by_path is not None:
        dref = {"byPath": {"path": by_path}}
    elif model_name:
        dref = {"byPath": {"path": f"../{model_name}.SemanticModel"}}
    else:
        dref = {"byConnection": {"connectionString": "semanticmodelid=00000000-0000-0000-0000-000000000000"}}
    write(rp / "definition.pbir", {"$schema": S_PBIR, "version": "4.0", "datasetReference": dref})
    d = rp / "definition"
    write(d / "version.json", {"$schema": S_VERSION, "version": "2.0.0"})
    rep: dict[str, Any] = {"$schema": S_REPORT, "themeCollection": {}}
    if report_filters:
        rep["filterConfig"] = {"filters": report_filters}
    write(d / "report.json", rep)
    write(d / "pages" / "pages.json", {"$schema": S_PAGES, "pageOrder": [p["name"] for p in pages],
                                        "activePageName": pages[0]["name"] if pages else None})
    for p in pages:
        pj: dict[str, Any] = {"$schema": S_PAGE, "name": p["name"], "displayName": p["display"],
                              "displayOption": "FitToPage", "height": 720, "width": 1280}
        if p.get("filters"):
            pj["filterConfig"] = {"filters": p["filters"]}
        write(d / "pages" / p["name"] / "page.json", pj)
        for v in p.get("visuals", []):
            if isinstance(v, tuple):  # (nome, conteúdo bruto) para arquivos malformados
                write(d / "pages" / p["name"] / "visuals" / v[0] / "visual.json", v[1])
            else:
                write(d / "pages" / p["name"] / "visuals" / v["name"] / "visual.json", v)
    for rel_path, content in (extra or {}).items():
        write(rp / rel_path, content)
    return rp


def write_pbip(root: Path, name: str) -> None:
    write(root / f"{name}.pbip", {"$schema": S_PBIP, "version": "1.0",
                                  "artifacts": [{"report": {"path": f"{name}.Report"}}],
                                  "settings": {"enableAutoRecovery": True}})
    write(root / ".gitignore", "**/.pbi/localSettings.json\n**/.pbi/cache.abf\n")
