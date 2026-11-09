"""Carregamento de modelos semânticos (*.SemanticModel): TMDL ou TMSL (model.bim).

Referência: https://learn.microsoft.com/power-bi/developer/projects/projects-dataset
- definition.pbism (obrigatório) com `version` (1.0 => TMSL; 4.0+ => TMSL ou TMDL);
- pasta definition/ com arquivos .tmdl (formato TMDL);
- model.bim (formato TMSL, JSON).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pbip_forensics.models import Column, ForensicsError, Measure, ParseIssue, Relationship, SemanticModel, Table
from pbip_forensics.parsers.tmdl import detect_m_sources, parse_tmdl_texts
from pbip_forensics.security.safety import DEFAULT_MAX_FILE_BYTES, read_json, read_text, rel


def _join_expr(value: Any) -> str:
    """No TMSL, expressões podem ser string ou lista de linhas."""
    if isinstance(value, list):
        return "\n".join(str(v) for v in value)
    return str(value) if value is not None else ""


def parse_bim(data: dict[str, Any], path: str) -> tuple[list[Table], list[Relationship], list[str], list[str]]:
    """Converte o JSON TMSL (model.bim) para as estruturas internas."""
    model = data.get("model", data) if isinstance(data, dict) else {}
    tables: list[Table] = []
    for t in model.get("tables", []) or []:
        if not isinstance(t, dict) or "name" not in t:
            continue
        tbl = Table(name=str(t["name"]), path=path, is_hidden=bool(t.get("isHidden", False)))
        if t.get("calculationGroup"):
            tbl.is_calculation_group = True
        for c in t.get("columns", []) or []:
            if not isinstance(c, dict) or "name" not in c:
                continue
            calc = c.get("type") == "calculated" or "expression" in c
            tbl.columns.append(Column(
                table=tbl.name, name=str(c["name"]), data_type=(c.get("dataType") or None),
                is_hidden=bool(c.get("isHidden", False)), is_calculated=calc,
                expression=_join_expr(c.get("expression")) if calc else None, path=path,
            ))
        for m in t.get("measures", []) or []:
            if not isinstance(m, dict) or "name" not in m:
                continue
            tbl.measures.append(Measure(
                table=tbl.name, name=str(m["name"]), expression=_join_expr(m.get("expression")),
                format_string=m.get("formatString"), display_folder=m.get("displayFolder"),
                is_hidden=bool(m.get("isHidden", False)), path=path,
            ))
        for h in t.get("hierarchies", []) or []:
            if isinstance(h, dict) and "name" in h:
                tbl.hierarchies.append(str(h["name"]))
        for p in t.get("partitions", []) or []:
            src = p.get("source", {}) if isinstance(p, dict) else {}
            kind = str(src.get("type", "unknown")).lower()
            tbl.partition_kinds.append(kind)
            if kind == "calculated":
                tbl.is_calculated = True
            for s in detect_m_sources(_join_expr(src.get("expression"))):
                if s not in tbl.data_sources:
                    tbl.data_sources.append(s)
        tables.append(tbl)
    rels: list[Relationship] = []
    for r in model.get("relationships", []) or []:
        if not isinstance(r, dict):
            continue
        rels.append(Relationship(
            id=str(r.get("name", "")), from_table=str(r.get("fromTable", "")),
            from_column=str(r.get("fromColumn", "")), to_table=str(r.get("toTable", "")),
            to_column=str(r.get("toColumn", "")), is_active=bool(r.get("isActive", True)),
            cross_filter=str(r.get("crossFilteringBehavior", "oneDirection")),
            from_cardinality=str(r.get("fromCardinality", "many")).lower(),
            to_cardinality=str(r.get("toCardinality", "one")).lower(), path=path,
        ))
    roles = [str(r.get("name")) for r in model.get("roles", []) or [] if isinstance(r, dict)]
    exprs = []
    for e in model.get("expressions", []) or []:
        if isinstance(e, dict) and "name" in e:
            srcs = detect_m_sources(_join_expr(e.get("expression")))
            exprs.append(f"{e['name']} ({', '.join(srcs)})" if srcs else str(e["name"]))
    return tables, rels, roles, exprs


def load_semantic_model(root: Path, folder: Path, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> SemanticModel:
    """Carrega um diretório *.SemanticModel sem modificar nenhum arquivo."""
    name = folder.name[: -len(".SemanticModel")] if folder.name.endswith(".SemanticModel") else folder.name
    model = SemanticModel(name=name, path=rel(root, folder))
    pbism = folder / "definition.pbism"
    if pbism.is_file():
        try:
            meta = read_json(root, pbism, max_bytes)
            model.pbism_version = str(meta.get("version")) if isinstance(meta, dict) else None
        except (json.JSONDecodeError, UnicodeDecodeError, ForensicsError) as exc:
            model.issues.append(ParseIssue(rel(root, pbism), f"Invalid definition.pbism: {exc}"))
    else:
        model.issues.append(ParseIssue(model.path, "definition.pbism not found", kind="structure"))

    definition = folder / "definition"
    bim = folder / "model.bim"
    if definition.is_dir():
        model.format = "tmdl"
        texts: list[tuple[str, str]] = []
        for f in sorted(definition.rglob("*.tmdl")):
            relp = rel(root, f)
            if "cultures" in f.relative_to(definition).parts:
                continue  # metadados linguísticos: irrelevantes para a auditoria
            if f.is_symlink():
                model.issues.append(ParseIssue(relp, "Symlink not followed", kind="security"))
                continue
            try:
                texts.append((relp, read_text(root, f, max_bytes)))
            except (ForensicsError, UnicodeDecodeError) as exc:
                model.issues.append(ParseIssue(relp, str(exc), kind="read-error"))
        result = parse_tmdl_texts(texts)
        model.tables = list(result.tables.values())
        model.relationships = result.relationships
        model.roles = result.roles
        model.shared_expressions = result.shared_expressions
        model.issues.extend(result.issues)
        if not texts:
            model.support = "limited"
            model.issues.append(ParseIssue(model.path, "definition/ folder has no .tmdl files", kind="structure"))
    elif bim.is_file():
        model.format = "tmsl"
        try:
            data = read_json(root, bim, max_bytes)
            model.tables, model.relationships, model.roles, model.shared_expressions = parse_bim(
                data, rel(root, bim))
        except (json.JSONDecodeError, UnicodeDecodeError, ForensicsError) as exc:
            model.support = "unsupported"
            model.issues.append(ParseIssue(rel(root, bim), f"Invalid model.bim: {exc}"))
    else:
        model.support = "unsupported"
        model.issues.append(ParseIssue(model.path, "No definition/ (TMDL) or model.bim (TMSL) found",
                                       kind="structure"))
    if any(i.kind == "parse-error" for i in model.issues) and model.support == "full":
        model.support = "limited"
    return model
