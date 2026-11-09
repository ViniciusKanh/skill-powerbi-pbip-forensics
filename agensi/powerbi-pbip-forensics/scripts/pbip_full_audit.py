#!/usr/bin/env python3
"""Power BI PBIP Forensics — pbip_full_audit.py (v1.0.0, Vinicius de Souza Santos).

Standalone, read-only script generated from the modular engine (src/pbip_forensics).
Requires only the Python 3.11+ standard library. Run with --help for usage.
Never modifies the analyzed project; writes only to --output (outside the project).
"""

# Arquivo gerado por tools/build_skill.py — não editar manualmente.
# Módulos incluídos: models, graph.model_graph, parsers.dax, analyzers.semantic, analyzers.inventory, analyzers.performance, analyzers.dax_rules, analyzers.model_rules, findings.issues, analyzers.stage_model, analyzers.filters, security.safety, parsers.pbir, analyzers.visual_rules, analyzers.stage_visual, findings.summary, analyzers.audit, parsers.tmdl, parsers.model_loader, discovery.detector, reporting.insights, reporting.html_report, reporting.render, automation, entrypoints.common, entrypoints.ep_full_audit

from __future__ import annotations

import sys

if sys.version_info < (3, 11):  # verificação antes de qualquer import dependente de versão
    sys.stderr.write("error: Python 3.11 or newer is required (found %d.%d)\n" % sys.version_info[:2])
    raise SystemExit(2)

import argparse
import contextlib
import hashlib
import html
import json
import math
import os
import re
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.models
# ----------------------------------------------------------------------
TOOL_NAME = "powerbi-pbip-forensics"
TOOL_VERSION = "1.0.0"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
STATUSES = ("confirmed", "potential", "inconclusive")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES)}


class ForensicsError(Exception):

    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class ParseIssue:

    path: str
    message: str
    line: int | None = None
    kind: str = "parse-error"


@dataclass
class Column:
    table: str
    name: str
    data_type: str | None = None
    is_hidden: bool = False
    is_calculated: bool = False
    expression: str | None = None
    path: str = ""
    line: int | None = None
    sort_by: str | None = None


@dataclass
class Measure:
    table: str
    name: str
    expression: str = ""
    format_string: str | None = None
    display_folder: str | None = None
    is_hidden: bool = False
    path: str = ""
    line: int | None = None


@dataclass
class Relationship:
    id: str
    from_table: str
    from_column: str
    to_table: str
    to_column: str
    is_active: bool = True
    cross_filter: str = "oneDirection"
    from_cardinality: str = "many"
    to_cardinality: str = "one"
    path: str = ""
    line: int | None = None

    @property
    def is_bidirectional(self) -> bool:
        return self.cross_filter.lower() == "bothdirections"

    def label(self) -> str:
        arrow = "<->" if self.is_bidirectional else "->"
        return (
            f"'{self.from_table}'[{self.from_column}] ({self.from_cardinality}) {arrow} "
            f"'{self.to_table}'[{self.to_column}] ({self.to_cardinality})"
        )


@dataclass
class Table:
    name: str
    path: str = ""
    line: int | None = None
    is_hidden: bool = False
    is_calculated: bool = False
    is_calculation_group: bool = False
    columns: list[Column] = field(default_factory=list)
    measures: list[Measure] = field(default_factory=list)
    hierarchies: list[str] = field(default_factory=list)
    hierarchy_columns: list[str] = field(default_factory=list)
    calc_source: str | None = None  # DAX da tabela calculada (apenas para análise de referências)
    partition_kinds: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)


@dataclass
class SemanticModel:
    name: str
    path: str
    format: str = "unknown"  # tmdl | tmsl | unknown
    support: str = "full"  # full | limited | unsupported
    pbism_version: str | None = None
    tables: list[Table] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    shared_expressions: list[str] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)

    def table(self, name: str) -> Table | None:
        low = name.lower()
        for tbl in self.tables:
            if tbl.name.lower() == low:
                return tbl
        return None

    def all_measures(self) -> list[Measure]:
        return [m for t in self.tables for m in t.measures]


@dataclass
class FieldRef:
    kind: str  # column | measure | aggregation | hierarchyLevel | unknown
    entity: str | None
    property: str | None
    role: str = ""
    usage: str = "projection"  # projection | filter | sort
    detail: str | None = None

    def key(self) -> str:
        return f"{self.entity}[{self.property}]"


@dataclass
class Visual:
    name: str
    page: str
    visual_type: str
    path: str
    title: str | None = None
    is_custom: bool = False
    is_group: bool = False
    fields: list[FieldRef] = field(default_factory=list)
    filter_count: int = 0
    limitations: list[str] = field(default_factory=list)


@dataclass
class Page:
    name: str
    display_name: str
    path: str
    visuals: list[Visual] = field(default_factory=list)
    filters: list[FieldRef] = field(default_factory=list)


@dataclass
class Report:
    name: str
    path: str
    format: str = "unknown"  # pbir | pbir-legacy | unknown
    support: str = "full"
    pbir_version: str | None = None
    dataset_ref: str | None = None  # caminho relativo ou "byConnection"
    model_path: str | None = None
    pages: list[Page] = field(default_factory=list)
    filters: list[FieldRef] = field(default_factory=list)
    extension_measures: list[str] = field(default_factory=list)
    custom_visual_ids: list[str] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)

    def visuals(self) -> list[Visual]:
        return [v for p in self.pages for v in p.visuals]


@dataclass
class Project:
    root: str
    pbip_files: list[str] = field(default_factory=list)
    reports: list[Report] = field(default_factory=list)
    models: list[SemanticModel] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def model_for(self, report: Report) -> SemanticModel | None:
        if report.model_path is None:
            return None
        for model in self.models:
            if model.path == report.model_path:
                return model
        return None


@dataclass
class Finding:

    rule_id: str
    title: str
    category: str
    severity: str
    status: str
    evidence: list[str]
    path: str
    object_ref: str
    explanation: str
    impact: str
    recommendation: str
    verification: str
    line: int | None = None
    confidence_note: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"Severidade inválida: {self.severity}")
        if self.status not in STATUSES:
            raise ValueError(f"Status inválido: {self.status}")
        if not self.id:
            self.id = stable_id(self.rule_id, self.path, self.object_ref)


def stable_id(rule_id: str, path: str, object_ref: str) -> str:
    digest = hashlib.sha1(f"{rule_id}|{path}|{object_ref}".encode(), usedforsecurity=False)
    return f"{rule_id}-{digest.hexdigest()[:8]}"


def to_jsonable(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, list):
        return [to_jsonable(o) for o in obj]
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    return obj


def sort_findings(findings: list[Finding]) -> list[Finding]:
    status_rank = {s: i for i, s in enumerate(STATUSES)}
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], status_rank[f.status], f.id))


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.graph.model_graph
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class Hop:

    src: str
    dst: str
    rel: Relationship
    along_default: bool  # True se segue o sentido one->many padrão
    allowed: bool  # o filtro realmente propaga neste sentido?

    def describe(self) -> str:
        state = "active" if self.rel.is_active else "INACTIVE"
        if not self.allowed and self.rel.is_active:
            state = "active, but cross-filter direction does not allow this way"
        return f"'{self.src}' -> '{self.dst}' via {self.rel.label()} [{state}]"


def _both(rel: Relationship) -> bool:
    return rel.is_bidirectional or (rel.from_cardinality == "one" and rel.to_cardinality == "one")


class ModelGraph:

    def __init__(self, model: SemanticModel) -> None:
        self.model = model
        self.names = {t.name.lower(): t.name for t in model.tables}
        self.rels = [r for r in model.relationships
                     if r.from_table.lower() in self.names and r.to_table.lower() in self.names]

    def canon(self, name: str) -> str | None:
        return self.names.get(name.lower())

    # ----------------------------------------------------------- vizinhança
    def hops_from(self, table: str, include_inactive: bool = False,
                  activated: set[str] | None = None) -> list[Hop]:
        activated = activated or set()
        out = []
        low = table.lower()
        for r in self.rels:
            active = r.is_active or r.id in activated
            if not active and not include_inactive:
                continue
            if r.to_table.lower() == low:
                out.append(Hop(self.names[low], r.from_table, r, True, active))
            if r.from_table.lower() == low:
                out.append(Hop(self.names[low], r.to_table, r, False, active and _both(r)))
        return out

    def filter_paths(self, src: str, dst: str, activated: set[str] | None = None,
                     max_len: int = 6, limit: int = 20) -> list[list[Hop]]:
        return self._paths(src, dst, max_len, limit, only_allowed=True, activated=activated)

    def all_paths(self, src: str, dst: str, max_len: int = 6, limit: int = 20) -> list[list[Hop]]:
        return self._paths(src, dst, max_len, limit, only_allowed=False, activated=None)

    def _paths(self, src: str, dst: str, max_len: int, limit: int, only_allowed: bool,
               activated: set[str] | None) -> list[list[Hop]]:
        s, d = self.canon(src), self.canon(dst)
        if s is None or d is None or s == d:
            return []
        found: list[list[Hop]] = []

        def dfs(node: str, path: list[Hop], seen: set[str]) -> None:
            if len(found) >= limit or len(path) >= max_len:
                return
            for hop in self.hops_from(node, include_inactive=not only_allowed, activated=activated):
                if only_allowed and not hop.allowed:
                    continue
                nxt = hop.dst.lower()
                if nxt in seen:
                    continue
                if nxt == d.lower():
                    found.append([*path, hop])
                    continue
                dfs(hop.dst, [*path, hop], seen | {nxt})

        dfs(s, [], {s.lower()})
        found.sort(key=lambda p: (len(p), [h.rel.id for h in p]))
        return found

    # ------------------------------------------------------------ estrutura
    def degree(self, table: str) -> int:
        low = table.lower()
        return sum(1 for r in self.rels if low in (r.from_table.lower(), r.to_table.lower()))

    def components(self, include_inactive: bool = True) -> list[list[str]]:
        adj: dict[str, set[str]] = defaultdict(set)
        for r in self.rels:
            if r.is_active or include_inactive:
                a, b = r.from_table.lower(), r.to_table.lower()
                adj[a].add(b)
                adj[b].add(a)
        seen: set[str] = set()
        comps = []
        for low in sorted(self.names):
            if low in seen:
                continue
            stack, comp = [low], []
            seen.add(low)
            while stack:
                cur = stack.pop()
                comp.append(self.names[cur])
                for nb in adj[cur]:
                    if nb not in seen:
                        seen.add(nb)
                        stack.append(nb)
            comps.append(sorted(comp))
        return comps

    def undirected_cycles(self) -> list[list[Relationship]]:
        parent: dict[str, tuple[str, Relationship] | None] = {}
        depth: dict[str, int] = {}
        cycles: list[list[Relationship]] = []
        adj: dict[str, list[tuple[str, Relationship]]] = defaultdict(list)
        for r in self.rels:
            if r.is_active:
                a, b = r.from_table.lower(), r.to_table.lower()
                adj[a].append((b, r))
                adj[b].append((a, r))
        used: set[str] = set()
        for start in sorted(adj):
            if start in parent:
                continue
            parent[start], depth[start] = None, 0
            stack = [start]
            while stack:
                cur = stack.pop()
                for nb, r in adj[cur]:
                    if r.id in used:
                        continue
                    used.add(r.id)
                    if nb not in parent:
                        parent[nb], depth[nb] = (cur, r), depth[cur] + 1
                        stack.append(nb)
                    else:
                        cycles.append(self._cycle(cur, nb, r, parent, depth))
        return cycles

    @staticmethod
    def _cycle(a: str, b: str, closing: Relationship, parent: dict[str, tuple[str, Relationship] | None],
               depth: dict[str, int]) -> list[Relationship]:
        rels = [closing]
        while a != b:
            if depth[a] >= depth[b]:
                step = parent[a]
                assert step is not None
                rels.append(step[1])
                a = step[0]
            else:
                step = parent[b]
                assert step is not None
                rels.append(step[1])
                b = step[0]
        return rels

    def table_role(self, table: str) -> str:
        low = table.lower()
        many = one = False
        for r in self.rels:
            if r.from_table.lower() == low:
                many = many or r.from_cardinality == "many"
                one = one or r.from_cardinality == "one"
            if r.to_table.lower() == low:
                one = one or r.to_cardinality == "one"
                many = many or r.to_cardinality == "many"
        if not many and not one:
            return "disconnected"
        if many and one:
            return "bridge"
        return "fact" if many else "dimension"

    def find_relationship(self, t1: str, c1: str, t2: str, c2: str) -> Relationship | None:
        a = (t1.lower(), c1.lower())
        b = (t2.lower(), c2.lower())
        for r in self.model.relationships:
            x = (r.from_table.lower(), r.from_column.lower())
            y = (r.to_table.lower(), r.to_column.lower())
            if (x, y) in ((a, b), (b, a)):
                return r
        return None


def strongly_connected(adj: dict[str, set[str]]) -> list[list[str]]:
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[list[str]] = []
    counter = 0
    for root in sorted(adj):
        if root in index:
            continue
        work = [(root, iter(sorted(adj.get(root, ()))))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for nb in it:
                if nb not in index:
                    index[nb] = low[nb] = counter
                    counter += 1
                    stack.append(nb)
                    on_stack.add(nb)
                    work.append((nb, iter(sorted(adj.get(nb, ())))))
                    advanced = True
                    break
                if nb in on_stack:
                    low[node] = min(low[node], index[nb])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                comp = []
                while True:
                    top = stack.pop()
                    on_stack.discard(top)
                    comp.append(top)
                    if top == node:
                        break
                if len(comp) > 1 or node in adj.get(node, set()):
                    result.append(sorted(comp))
    return result


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.parsers.dax
# ----------------------------------------------------------------------
DAX_KEYWORDS = {"VAR", "RETURN", "IN", "NOT", "AND", "OR", "TRUE", "FALSE", "DEFINE", "EVALUATE",
                "MEASURE", "ORDER", "BY", "ASC", "DESC", "START", "AT", "COLUMN", "TABLE", "BLANK"}
ITERATORS = {"SUMX", "AVERAGEX", "MINX", "MAXX", "COUNTX", "COUNTAX", "PRODUCTX", "CONCATENATEX",
             "RANKX", "FILTER", "ADDCOLUMNS", "SELECTCOLUMNS", "GENERATE", "GENERATEALL",
             "MEDIANX", "PERCENTILEX.INC", "PERCENTILEX.EXC", "STDEVX.P", "STDEVX.S", "VARX.P", "VARX.S",
             "GEOMEANX", "TOPN"}
FILTER_REMOVERS = {"ALL", "REMOVEFILTERS", "ALLEXCEPT", "ALLSELECTED", "ALLNOBLANKROW",
                   "ALLCROSSFILTERED"}
CALC_FUNCS = {"CALCULATE", "CALCULATETABLE"}


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    pos: int
    line: int


@dataclass
class Call:
    name: str
    index: int  # índice do token identificador na lista significativa
    parent: int | None
    parent_arg: int | None
    args: list[tuple[int, int]] = field(default_factory=list)
    closed: bool = False


@dataclass
class ColumnRef:
    table: str | None
    name: str
    index: int


@dataclass
class DaxInfo:
    tokens: list[Token]
    calls: list[Call]
    refs: list[ColumnRef]  # table=None => referência não qualificada [X]
    table_refs: list[tuple[str, int]]
    strings: set[str]
    variables: set[str]
    errors: list[str]

    def arg_tokens(self, call: Call, arg: int) -> list[Token]:
        if arg >= len(call.args):
            return []
        s, e = call.args[arg]
        return self.tokens[s:e]

    def refs_in(self, start: int, end: int) -> list[ColumnRef]:
        return [r for r in self.refs if start <= r.index < end]

    def ancestors(self, call_idx: int) -> list[tuple[int, int | None]]:
        out = []
        cur = self.calls[call_idx]
        while cur.parent is not None:
            parent_idx = cur.parent
            out.append((parent_idx, cur.parent_arg))
            cur = self.calls[parent_idx]
        return out


def tokenize(text: str) -> tuple[list[Token], list[str]]:
    toks: list[Token] = []
    errors: list[str] = []
    i, n, line = 0, len(text), 1

    def until_quote(q: str, start: int) -> tuple[str, int, bool]:
        j, buf = start, []
        while j < n:
            if text[j] == q:
                if j + 1 < n and text[j + 1] == q:
                    buf.append(q)
                    j += 2
                    continue
                return "".join(buf), j + 1, True
            buf.append(text[j])
            j += 1
        return "".join(buf), j, False

    while i < n:
        ch = text[i]
        start_line = line
        if ch.isspace():
            j = i
            while j < n and text[j].isspace():
                j += 1
            toks.append(Token("WS", text[i:j], i, start_line))
        elif text.startswith("//", i) or text.startswith("--", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            toks.append(Token("COMMENT", text[i:j], i, start_line))
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                errors.append(f"Unterminated block comment at line {start_line}")
                j = n
            else:
                j += 2
            toks.append(Token("COMMENT", text[i:j], i, start_line))
        elif ch == '"':
            val, j, ok = until_quote('"', i + 1)
            if not ok:
                errors.append(f"Unterminated string at line {start_line}")
            toks.append(Token("STRING", val, i, start_line))
        elif ch == "'":
            val, j, ok = until_quote("'", i + 1)
            if not ok:
                errors.append(f"Unterminated quoted table name at line {start_line}")
            toks.append(Token("TABLE", val, i, start_line))
        elif ch == "[":
            j, buf, ok = i + 1, [], False
            while j < n:
                if text[j] == "]":
                    if j + 1 < n and text[j + 1] == "]":
                        buf.append("]")
                        j += 2
                        continue
                    j += 1
                    ok = True
                    break
                buf.append(text[j])
                j += 1
            if not ok:
                errors.append(f"Unterminated [reference] at line {start_line}")
            toks.append(Token("BRACKET", "".join(buf), i, start_line))
        elif ch.isdigit() or (ch == "." and i + 1 < n and text[i + 1].isdigit()):
            j = i
            while j < n and (text[j].isdigit() or text[j] in ".eE" or
                             (text[j] in "+-" and text[j - 1] in "eE")):
                j += 1
            toks.append(Token("NUMBER", text[i:j], i, start_line))
        elif ch.isalpha() or ch == "_":
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_."):
                j += 1
            toks.append(Token("IDENT", text[i:j], i, start_line))
        elif ch in "(){},;":
            kind = {"(": "LPAREN", ")": "RPAREN", "{": "LBRACE", "}": "RBRACE"}.get(ch, "COMMA")
            j = i + 1
            toks.append(Token(kind, ch, i, start_line))
        else:
            two = text[i:i + 2]
            j = i + 2 if two in ("&&", "||", "<=", ">=", "<>", "==") else i + 1
            toks.append(Token("OP", text[i:j], i, start_line))
        line += text.count("\n", i, j)
        i = j
    return toks, errors


def analyze_dax(expression: str) -> DaxInfo:
    all_toks, errors = tokenize(expression or "")
    sig = [t for t in all_toks if t.kind not in ("WS", "COMMENT")]
    calls: list[Call] = []
    refs: list[ColumnRef] = []
    table_refs: list[tuple[str, int]] = []
    strings = {t.value for t in sig if t.kind == "STRING"}
    variables: set[str] = set()
    stack: list[tuple[int | None, int]] = []  # (índice da chamada ou None, início do argumento)
    pending: int | None = None  # chamada aguardando o '(' de abertura

    for i, tok in enumerate(sig):
        nxt = sig[i + 1] if i + 1 < len(sig) else None
        prev = sig[i - 1] if i > 0 else None
        if tok.kind == "IDENT" and prev is not None and prev.kind == "IDENT" and prev.value.upper() == "VAR":
            variables.add(tok.value)
        if tok.kind == "IDENT" and nxt is not None and nxt.kind == "LPAREN":
            parent = next((c for c, _ in reversed(stack) if c is not None), None)
            parent_arg = len(calls[parent].args) if parent is not None else None
            calls.append(Call(tok.value.upper(), i, parent, parent_arg))
            pending = len(calls) - 1
            continue
        if tok.kind == "LPAREN":
            stack.append((pending, i + 1))
            pending = None
        elif tok.kind == "COMMA" and stack:
            cidx, astart = stack[-1]
            if cidx is not None:
                calls[cidx].args.append((astart, i))
                stack[-1] = (cidx, i + 1)
        elif tok.kind == "RPAREN":
            if not stack:
                errors.append(f"Unbalanced ')' at line {tok.line}")
                continue
            cidx, astart = stack.pop()
            if cidx is not None:
                if i > astart or calls[cidx].args:
                    calls[cidx].args.append((astart, i))
                calls[cidx].closed = True
        elif tok.kind == "BRACKET":
            if prev is not None and prev.kind in ("TABLE", "IDENT") and \
                    prev.value.upper() not in DAX_KEYWORDS:
                refs.append(ColumnRef(prev.value, tok.value, i))
            else:
                refs.append(ColumnRef(None, tok.value, i))
        elif tok.kind in ("TABLE", "IDENT") and (nxt is None or nxt.kind not in ("BRACKET", "LPAREN")):
            if tok.kind == "TABLE" or tok.value.upper() not in DAX_KEYWORDS:
                table_refs.append((tok.value, i))
    if stack:
        errors.append("Unbalanced '(' in expression")
    return DaxInfo(sig, calls, refs, table_refs, strings, variables, errors)


def normalized_tokens(expression: str) -> list[str]:
    toks, _ = tokenize(expression or "")
    return [f"{t.kind}:{t.value.upper() if t.kind == 'IDENT' else t.value}" for t in toks
            if t.kind not in ("WS", "COMMENT")]


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.analyzers.semantic
# ----------------------------------------------------------------------
# Funções que criam colunas implícitas ([Value], [Date]...) em tabelas temporárias.
_IMPLICIT_COLUMN_FUNCS = {"GENERATESERIES", "CALENDAR", "CALENDARAUTO", "DATATABLE", "ROW"}
_MODIFIER_FUNCS = FILTER_REMOVERS | {"USERELATIONSHIP", "CROSSFILTER", "KEEPFILTERS", "TREATAS"}
# Funções que apenas consultam/inspecionam valores (não definem a tabela agregada).
_PROBE_FUNCS = {"SELECTEDVALUE", "HASONEVALUE", "HASONEFILTER", "ISFILTERED", "ISCROSSFILTERED", "ISINSCOPE",
                "LOOKUPVALUE", "RELATED", "FIRSTNONBLANK", "LASTNONBLANK"}


@dataclass
class Modifier:

    function: str
    targets: list[str]
    context: str  # calculate-filter | filter-table | table-expression
    relationship: Relationship | None = None
    direction: str | None = None
    line: int | None = None


@dataclass
class ExprAnalysis:
    owner: str  # 'Tabela'[Objeto]
    kind: str  # measure | column
    table: str
    name: str
    path: str
    line: int | None
    expression: str
    info: DaxInfo
    measure_deps: list[str] = field(default_factory=list)
    column_refs: list[tuple[str, str]] = field(default_factory=list)
    base_tables: set[str] = field(default_factory=set)
    missing: list[tuple[str, str, str]] = field(default_factory=list)  # (texto, motivo, status)
    modifiers: list[Modifier] = field(default_factory=list)


class SemanticIndex:

    def __init__(self, model: SemanticModel) -> None:
        self.model = model
        self.graph = ModelGraph(model)
        self.measures: dict[str, Measure] = {}
        for m in model.all_measures():
            self.measures.setdefault(m.name.lower(), m)
        self.columns: dict[str, dict[str, Column]] = {}
        for t in model.tables:
            self.columns[t.name.lower()] = {c.name.lower(): c for c in t.columns}
        self.analyses: dict[str, ExprAnalysis] = {}
        self.column_analyses: list[ExprAnalysis] = []
        for m in model.all_measures():
            self.analyses[m.name.lower()] = self._analyze(m.table, m.name, "measure", m.expression, m.path, m.line)
        for t in model.tables:
            for c in t.columns:
                if c.is_calculated and c.expression:
                    self.column_analyses.append(
                        self._analyze(t.name, c.name, "column", c.expression, c.path, c.line))

    # ------------------------------------------------------------ resolução
    def table_name(self, name: str) -> str | None:
        tbl = self.model.table(name)
        return tbl.name if tbl else None

    def has_column(self, table: str, column: str) -> bool:
        return column.lower() in self.columns.get(table.lower(), {})

    def _analyze(self, table: str, name: str, kind: str, expr: str, path: str,
                 line: int | None) -> ExprAnalysis:
        info = analyze_dax(expr)
        ea = ExprAnalysis(f"'{table}'[{name}]", kind, table, name, path, line, expr, info)
        filter_ranges = self._filter_ranges(info)
        implicit = any(c.name in _IMPLICIT_COLUMN_FUNCS for c in info.calls) or \
            any(t.kind == "LBRACE" for t in info.tokens)
        local_names = {s.lower() for s in info.strings}

        def in_filter(idx: int) -> bool:
            return any(s <= idx < e for s, e in filter_ranges)

        for ref in info.refs:
            if ref.table is not None:
                tcanon = self.table_name(ref.table)
                if tcanon is None:
                    if ref.table in info.variables:
                        ea.missing.append((f"{ref.table}[{ref.name}]", "qualifier is a VAR name", "potential"))
                    else:
                        ea.missing.append((f"'{ref.table}'[{ref.name}]", f"table '{ref.table}' not found",
                                           "confirmed"))
                    continue
                if self.has_column(tcanon, ref.name):
                    col = self.columns[tcanon.lower()][ref.name.lower()]
                    ea.column_refs.append((tcanon, col.name))
                    if not in_filter(ref.index):
                        ea.base_tables.add(tcanon)
                elif ref.name.lower() in self.measures:
                    ea.measure_deps.append(self.measures[ref.name.lower()].name)
                else:
                    ea.missing.append((f"'{tcanon}'[{ref.name}]",
                                       f"no column or measure '{ref.name}' in table '{tcanon}'", "confirmed"))
                continue
            low = ref.name.lower()
            if low in self.measures:
                ea.measure_deps.append(self.measures[low].name)
            elif low in local_names or (implicit and (low.startswith("value") or low == "date")):
                continue  # coluna criada na própria expressão (ADDCOLUMNS, GENERATESERIES...)
            elif kind == "column" and self.has_column(table, ref.name):
                ea.column_refs.append((table, self.columns[table.lower()][low].name))
            else:
                owners = [t for t, cols in self.columns.items() if low in cols]
                if owners:
                    owner_tbl = self.model.table(owners[0])
                    if owner_tbl is not None and len(owners) == 1:
                        ea.column_refs.append((owner_tbl.name, self.columns[owners[0]][low].name))
                        if not in_filter(ref.index):
                            ea.base_tables.add(owner_tbl.name)
                else:
                    ea.missing.append((f"[{ref.name}]", "no measure or column with this name in the model",
                                       "confirmed"))
        for tref, tidx in info.table_refs:
            canon = self.table_name(tref)
            if canon and tref not in info.variables and not in_filter(tidx):
                ea.base_tables.add(canon)
        ea.measure_deps = sorted(set(ea.measure_deps), key=str.lower)
        ea.modifiers = self._modifiers(info)
        return ea

    @staticmethod
    def _filter_ranges(info: DaxInfo) -> list[tuple[int, int]]:
        ranges = []
        for call in info.calls:
            if call.name in CALC_FUNCS:
                ranges.extend(call.args[1:])
            elif (call.name in _MODIFIER_FUNCS or call.name in _PROBE_FUNCS) and call.args:
                ranges.append((call.args[0][0], call.args[-1][1]))
        return ranges

    def _modifiers(self, info: DaxInfo) -> list[Modifier]:
        mods = []
        for ci, call in enumerate(info.calls):
            if call.name not in _MODIFIER_FUNCS:
                continue
            parent = info.calls[call.parent] if call.parent is not None else None
            if parent and parent.name in CALC_FUNCS and (call.parent_arg or 0) >= 1:
                ctx = "calculate-filter"
            elif parent and parent.name == "FILTER" and call.parent_arg == 0:
                ctx = "filter-table"
            else:
                ctx = "table-expression"
            targets: list[str] = []
            refs = []
            for a in range(len(call.args)):
                toks = info.arg_tokens(call, a)
                s, e = call.args[a]
                arefs = info.refs_in(s, e)
                refs.extend(arefs)
                if len(toks) == 1 and toks[0].kind in ("TABLE", "IDENT") and \
                        toks[0].value.upper() not in DAX_KEYWORDS:
                    canon = self.table_name(toks[0].value)
                    targets.append(f"'{canon}'" if canon else toks[0].value)
                for r in arefs:
                    targets.append(f"'{r.table}'[{r.name}]" if r.table else f"[{r.name}]")
            mod = Modifier(call.name, targets, ctx, line=info.tokens[call.index].line)
            if call.name in ("USERELATIONSHIP", "CROSSFILTER") and len(refs) >= 2 and refs[0].table \
                    and refs[1].table:
                mod.relationship = self.graph.find_relationship(refs[0].table, refs[0].name,
                                                                refs[1].table, refs[1].name)
            if call.name == "CROSSFILTER" and len(call.args) >= 3:
                toks = info.arg_tokens(call, 2)
                mod.direction = toks[0].value.upper() if toks else None
            mods.append(mod)
            _ = ci
        return mods

    # ----------------------------------------------------------- consultas
    def measure_closure(self, name: str) -> list[str]:
        seen: set[str] = set()
        stack = [name.lower()]
        while stack:
            cur = self.analyses.get(stack.pop())
            if cur is None:
                continue
            for dep in cur.measure_deps:
                if dep.lower() not in seen:
                    seen.add(dep.lower())
                    stack.append(dep.lower())
        seen.discard(name.lower())
        return sorted((self.measures[s].name for s in seen if s in self.measures), key=str.lower)

    def dependents(self, name: str) -> list[str]:
        out = []
        for low, ea in self.analyses.items():
            if low != name.lower() and name.lower() in {d.lower() for d in self.measure_closure(ea.name)}:
                out.append(ea.name)
        return sorted(out, key=str.lower)

    def base_tables(self, name: str) -> set[str]:
        tables: set[str] = set()
        for m in [name, *self.measure_closure(name)]:
            ea = self.analyses.get(m.lower())
            if ea:
                tables |= ea.base_tables
        return tables

    def modifiers_for(self, name: str) -> list[tuple[str, Modifier]]:
        out: list[tuple[str, Modifier]] = []
        for m in [name, *self.measure_closure(name)]:
            ea = self.analyses.get(m.lower())
            if ea:
                out.extend((ea.name, mod) for mod in ea.modifiers)
        return out

    def depth(self, name: str, _seen: frozenset[str] = frozenset()) -> int:
        ea = self.analyses.get(name.lower())
        if ea is None or name.lower() in _seen:
            return 0
        deps = [self.depth(d, _seen | {name.lower()}) for d in ea.measure_deps]
        return 1 + (max(deps) if deps else 0)

    def measure_cycles(self) -> list[list[str]]:
        adj = {k: {d.lower() for d in v.measure_deps} for k, v in self.analyses.items()}
        return [[self.measures[x].name for x in comp] for comp in strongly_connected(adj)]


def build_indexes(project: Project) -> dict[str, SemanticIndex]:
    return {m.path: SemanticIndex(m) for m in project.models}


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.analyzers.inventory
# ----------------------------------------------------------------------
def _complexity(ea: Any) -> dict[str, int]:
    info = ea.info
    nest = 0
    for i in range(len(info.calls)):
        nest = max(nest, len(info.ancestors(i)) + 1)
    iters = sum(1 for c in info.calls if c.name in ITERATORS)
    calcs = sum(1 for c in info.calls if c.name in CALC_FUNCS)
    lines = ea.expression.count("\n") + 1 if ea.expression else 0
    score = len(info.calls) + 2 * iters + 2 * calcs + 3 * nest + lines // 5 + len(ea.measure_deps)
    return {"tokens": len(info.tokens), "calls": len(info.calls), "iterators": iters, "calculates": calcs,
            "max_nesting": nest, "lines": lines, "score": score}


def build_inventory(project: Project, indexes: dict[str, SemanticIndex]) -> dict[str, Any]:
    models = []
    for m in project.models:
        idx = indexes.get(m.path)
        tables = []
        for t in m.tables:
            tables.append({
                "name": t.name, "path": t.path, "line": t.line, "role": idx.graph.table_role(t.name) if idx else None,
                "is_hidden": t.is_hidden, "is_calculated": t.is_calculated,
                "is_calculation_group": t.is_calculation_group, "columns": [c.name for c in t.columns],
                "hidden_columns": [c.name for c in t.columns if c.is_hidden],
                "calculated_columns": [c.name for c in t.columns if c.is_calculated],
                "measures": [x.name for x in t.measures], "hierarchies": t.hierarchies,
                "partition_kinds": t.partition_kinds, "data_sources": t.data_sources})
        measures = []
        for x in m.all_measures():
            ea = idx.analyses.get(x.name.lower()) if idx else None
            measures.append({"table": x.table, "name": x.name, "path": x.path, "line": x.line,
                             "format_string": x.format_string, "complexity": _complexity(ea) if ea else None,
                             "display_folder": x.display_folder, "is_hidden": x.is_hidden,
                             "measure_dependencies": ea.measure_deps if ea else [],
                             "column_references": [f"'{a}'[{b}]" for a, b in ea.column_refs] if ea else [],
                             "depth": idx.depth(x.name) if idx else None})
        models.append({
            "name": m.name, "path": m.path, "format": m.format, "support": m.support,
            "pbism_version": m.pbism_version, "tables": tables, "measures": measures,
            "relationships": [{"id": r.id, "from": f"'{r.from_table}'[{r.from_column}]",
                               "to": f"'{r.to_table}'[{r.to_column}]", "is_active": r.is_active,
                               "cross_filter": r.cross_filter,
                               "cardinality": f"{r.from_cardinality}:{r.to_cardinality}",
                               "path": r.path, "line": r.line} for r in m.relationships],
            "roles": m.roles, "shared_expressions": m.shared_expressions,
            "components": idx.graph.components() if idx else []})
    reports = []
    for r in project.reports:
        reports.append({
            "name": r.name, "path": r.path, "format": r.format, "support": r.support,
            "pbir_version": r.pbir_version, "dataset_reference": r.dataset_ref, "model_path": r.model_path,
            "report_filters": [f.key() for f in r.filters], "extension_measures": r.extension_measures,
            "pages": [{"name": p.name, "display_name": p.display_name, "path": p.path,
                       "page_filters": [f.key() for f in p.filters],
                       "visuals": [{"name": v.name, "title": v.title, "type": v.visual_type, "path": v.path,
                                    "is_custom": v.is_custom, "field_count": len(v.fields),
                                    "visual_filters": v.filter_count, "limitations": v.limitations}
                                   for v in p.visuals]} for p in r.pages]})
    counts = {
        "pbip_files": len(project.pbip_files), "reports": len(project.reports),
        "pages": sum(len(r.pages) for r in project.reports),
        "visuals": sum(len(r.visuals()) for r in project.reports),
        "semantic_models": len(project.models), "tables": sum(len(m.tables) for m in project.models),
        "columns": sum(len(t.columns) for m in project.models for t in m.tables),
        "measures": sum(len(m.all_measures()) for m in project.models),
        "relationships": sum(len(m.relationships) for m in project.models),
    }
    return {"counts": counts, "pbip_files": project.pbip_files, "models": models, "reports": reports,
            "skipped_items": project.skipped}


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.analyzers.performance
# ----------------------------------------------------------------------
LIFECYCLE = "Visual Container Lifecycle"
CATEGORY_BY_EVENT = {
    "Execute DAX Query": "dax_query_ms",
    "Execute Direct Query": "direct_query_ms",
    "Render": "visual_display_ms",
    "Evaluated Parameters": "evaluated_parameters_ms",
}
DEFAULT_THRESHOLDS = {"high_ms": 3000.0, "medium_ms": 1000.0}


def _ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    # Python 3.11 aceita frações com até 6 dígitos; normaliza frações maiores.
    if "." in text:
        head, _, rest = text.partition(".")
        digits = "".join(ch for ch in rest if ch.isdigit())
        tz = rest[len(digits):]
        text = f"{head}.{digits[:6].ljust(6, '0')}{tz}"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _dur(ev: dict[str, Any]) -> float | None:
    s, e = _ts(ev.get("start")), _ts(ev.get("end"))
    if s is None or e is None:
        return None
    return round((e - s).total_seconds() * 1000.0, 3)


def parse_performance(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("events"), list):
        raise ForensicsError("Invalid Performance Analyzer export: expected an object with an 'events' list", 5)
    events = [e for e in data["events"] if isinstance(e, dict)]
    by_id = {str(e.get("id")): e for e in events if e.get("id") is not None}
    children: dict[str, list[dict[str, Any]]] = {}
    for e in events:
        if e.get("parentId") is not None:
            children.setdefault(str(e["parentId"]), []).append(e)
    warnings: list[str] = []
    skipped = sum(1 for e in data["events"] if not isinstance(e, dict))
    if skipped:
        warnings.append(f"{skipped} malformed event entries ignored")
    visuals: list[dict[str, Any]] = []
    for e in events:
        if e.get("name") != LIFECYCLE:
            continue
        metrics: dict[str, Any] = e["metrics"] if isinstance(e.get("metrics"), dict) else {}
        total = _dur(e)
        row: dict[str, Any] = {
            "visual_id": metrics.get("visualId"), "visual_title": metrics.get("visualTitle"),
            "visual_type": metrics.get("visualType"), "status": metrics.get("status"),
            "total_ms": total, "dax_query_ms": 0.0, "direct_query_ms": 0.0, "visual_display_ms": 0.0,
            "evaluated_parameters_ms": 0.0, "other_ms": None, "queries": [], "row_counts": [],
            "start": e.get("start"),
        }
        stack = list(children.get(str(e.get("id")), []))
        seen: set[int] = set()
        while stack:
            child = stack.pop()
            if id(child) in seen:
                continue
            seen.add(id(child))
            cat = CATEGORY_BY_EVENT.get(str(child.get("name")))
            d = _dur(child)
            if cat and d is not None:
                row[cat] = round(row[cat] + d, 3)
            cm: dict[str, Any] = child["metrics"] if isinstance(child.get("metrics"), dict) else {}
            if child.get("name") == "Execute DAX Query" and cm.get("QueryText"):
                row["queries"].append(str(cm["QueryText"])[:4000])
            if cm.get("RowCount") is not None:
                row["row_counts"].append(cm.get("RowCount"))
            stack.extend(children.get(str(child.get("id")), []))
        if total is not None:
            known = row["dax_query_ms"] + row["direct_query_ms"] + row["visual_display_ms"] + \
                row["evaluated_parameters_ms"]
            row["other_ms"] = round(max(total - known, 0.0), 3)
        else:
            warnings.append(f"Visual '{row['visual_title'] or row['visual_id']}' has no end timestamp")
        visuals.append(row)
    if not visuals:
        warnings.append("No 'Visual Container Lifecycle' events found; no per-visual timings available")
    orphan = sum(1 for e in events if e.get("parentId") is not None and str(e["parentId"]) not in by_id)
    if orphan:
        warnings.append(f"{orphan} events reference a parentId that is not in the file")
    visuals.sort(key=lambda r: (-(r["total_ms"] or 0.0), str(r["visual_title"])))
    return {"version": data.get("version"), "event_count": len(events),
            "user_actions": sum(1 for e in events if e.get("name") == "User Action"),
            "visuals": visuals, "warnings": warnings}


def dominant_component(row: dict[str, Any]) -> str | None:
    parts = {k: row.get(k) or 0.0 for k in ("dax_query_ms", "direct_query_ms", "visual_display_ms", "other_ms")}
    if not any(parts.values()):
        return None
    return max(parts, key=lambda k: parts[k])


_ACTIONS = {
    "dax_query_ms": "DAX query time dominates: copy the query (Copy query) into DAX query view or DAX Studio, "
                    "check server timings and review the measures involved.",
    "direct_query_ms": "DirectQuery time dominates: inspect the source query, indexes and gateway latency.",
    "visual_display_ms": "Visual display dominates: reduce data points/rows, simplify formatting or custom "
                         "visual rendering.",
    "other_ms": "'Other' dominates: the visual waited for other operations (queueing on the UI thread); reduce "
                "the number of visuals on the page or use bookmarks/drill-through.",
}


def performance_findings(perf: dict[str, Any], source: str, thresholds: dict[str, float] | None = None,
                         visual_names: dict[str, str] | None = None) -> list[Finding]:
    th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    out: list[Finding] = []
    for row in perf["visuals"]:
        total = row.get("total_ms")
        if total is None or total < th["medium_ms"]:
            continue
        sev = "HIGH" if total >= th["high_ms"] else "MEDIUM"
        dom = dominant_component(row)
        name = row.get("visual_title") or row.get("visual_id") or "(untitled)"
        page = (visual_names or {}).get(str(row.get("visual_id")), "")
        ev = [f"Measured total: {total:.1f} ms (threshold {th['medium_ms']:.0f}/{th['high_ms']:.0f} ms)",
              f"DAX query: {row['dax_query_ms']:.1f} ms; Direct query: {row['direct_query_ms']:.1f} ms; "
              f"Visual display: {row['visual_display_ms']:.1f} ms; Other (derived): {row['other_ms']:.1f} ms"]
        if page:
            ev.append(f"Mapped to project visual: {page}")
        out.append(Finding(
            "PERF001", f"Slow visual in recorded session: {name}", "Performance", sev, "confirmed", ev, source,
            f"perf/{row.get('visual_id')}/{row.get('start')}",
            "Duration measured by Performance Analyzer during the recorded session.",
            "Users experience delay on this visual; durations include queueing on the UI thread.",
            _ACTIONS.get(dom or "", "Review the visual."),
            "Record a new session with Performance Analyzer (clear cache by refreshing visuals) and compare."))
    return out


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.analyzers.dax_rules
# ----------------------------------------------------------------------
CAT_DAX = "DAX"
CAT_PERF = "DAX performance"
CAT_CTX = "Filter context"
_TOTAL_SENSITIVE = {"HASONEVALUE", "ISINSCOPE", "HASONEFILTER", "SELECTEDVALUE", "ISFILTERED"}


def _ref(model: SemanticModel, ea: ExprAnalysis) -> str:
    return f"{model.name}/{ea.kind}/{ea.table}/{ea.name}"


def _iter_table(ea: ExprAnalysis, call_idx: int) -> str | None:
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
    # DAX014 — medidas sem formato definido (consolidado por modelo)
    no_fmt = sorted((m for m in model.all_measures() if not m.format_string), key=lambda m: m.name.lower())
    if no_fmt:
        out.append(Finding(
            "DAX014", f"Measures without a format string ({len(no_fmt)} of {len(model.all_measures())})", CAT_DAX,
            "INFO", "potential", [f"[{m.name}]" for m in no_fmt[:25]], no_fmt[0].path, f"{model.name}/no-format",
            "These measures have no formatString; numeric results use the default format.",
            "Inconsistent number formatting across visuals (decimals, currency, percentages).",
            "Set a format string on numeric measures (text/color measures do not need one).",
            "Review the measures in the Model view > Properties > Format."))
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
            sev = "INFO"  # comportamento esperado do Power BI; serve de alerta, não de defeito
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


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.analyzers.model_rules
# ----------------------------------------------------------------------
CAT_REL = "Relationships"
CAT_MODEL = "Model structure"


def _rel_ref(model: SemanticModel, rid: str) -> str:
    return f"{model.name}/relationship/{rid}"


def model_findings(model: SemanticModel, idx: SemanticIndex) -> list[Finding]:
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


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.findings.issues
# ----------------------------------------------------------------------
_ISSUE_RULES = {
    "parse-error": ("PRS001", "MEDIUM", "confirmed", "File could not be fully parsed"),
    "read-error": ("PRS001", "MEDIUM", "confirmed", "File could not be read"),
    "structure": ("PRS002", "LOW", "confirmed", "Project structure issue"),
    "unsupported": ("PRS003", "INFO", "confirmed", "Unsupported artifact"),
    "limited-support": ("PRS004", "INFO", "inconclusive", "Limited support for this format"),
    "security": ("SEC001", "INFO", "confirmed", "Item skipped by security policy"),
}


def issue_findings(issues: list[ParseIssue]) -> list[Finding]:
    out = []
    for iss in issues:
        rule = _ISSUE_RULES.get(iss.kind)
        if rule is None:
            continue
        rid, sev, status, title = rule
        out.append(Finding(
            rid, f"{title}: {iss.path}", "Parsing", sev, status, [iss.message], iss.path,
            f"issue/{iss.path}/{iss.line}/{iss.message[:40]}",
            "The engine could not interpret this file or structure as documented.",
            "Objects in this file are missing from the analysis; related findings may be incomplete.",
            "Open and re-save the project in a current Power BI Desktop, or fix the file manually.",
            "Validate the file against its published JSON schema or open it in Power BI Desktop.", line=iss.line))
    return out


def collect_issues(project: Project) -> list[ParseIssue]:
    issues = list(project.issues)
    for m in project.models:
        issues.extend(m.issues)
    for r in project.reports:
        issues.extend(r.issues)
    return issues


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.analyzers.stage_model
# ----------------------------------------------------------------------
BASE_LIMITATIONS = [
    "Static analysis only: DAX is not executed and no data values are read.",
    "Filter-propagation results are derived from relationship metadata, not from query plans.",
]


def model_stage(project: Project, indexes: dict[str, SemanticIndex]) -> tuple[list[Finding], list[str]]:
    findings = issue_findings(collect_issues(project))
    limitations: list[str] = []
    for m in project.models:
        findings.extend(model_findings(m, indexes[m.path]))
        findings.extend(dax_findings(m, indexes[m.path]))
        if any(r.cross_filter.lower() == "automatic" for r in m.relationships):
            limitations.append(f"Model '{m.name}': crossFilteringBehavior 'automatic' treated as single direction.")
    return findings, limitations


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.analyzers.filters
# ----------------------------------------------------------------------
def _path_text(path: list[Hop]) -> str:
    return " => ".join(h.describe() for h in path)


def activated_relationships(idx: SemanticIndex, measure: str | None) -> set[str]:
    if not measure:
        return set()
    ids = set()
    for _, mod in idx.modifiers_for(measure):
        if mod.relationship is not None and mod.function == "USERELATIONSHIP":
            ids.add(mod.relationship.id)
    return ids


def reaches(idx: SemanticIndex, src: str, dst: str, measure: str | None = None) -> bool:
    if src.lower() == dst.lower():
        return True
    return bool(idx.graph.filter_paths(src, dst, activated_relationships(idx, measure), limit=1))


def investigate_filter(idx: SemanticIndex, from_table: str, to_table: str | None = None,
                       measure: str | None = None, visual: Visual | None = None) -> dict[str, Any]:
    g = idx.graph
    src = g.canon(from_table)
    if src is None:
        raise ForensicsError(f"Table not found in model: {from_table}", 2)
    mcanon = None
    if measure:
        m = idx.measures.get(measure.lower())
        if m is None:
            raise ForensicsError(f"Measure not found in model: {measure}", 2)
        mcanon = m.name
    targets: list[str] = []
    if to_table:
        t = g.canon(to_table)
        if t is None:
            raise ForensicsError(f"Table not found in model: {to_table}", 2)
        targets.append(t)
    if mcanon:
        targets.extend(sorted(idx.base_tables(mcanon) - set(targets)))
    if not targets:
        raise ForensicsError("Provide --to-table and/or --measure", 2)

    evidence: list[str] = []
    hypotheses: list[dict[str, Any]] = []
    activated = activated_relationships(idx, mcanon)
    if mcanon:
        bases = ", ".join(sorted(idx.base_tables(mcanon))) or "(none detected)"
        evidence.append(f"Measure {mcanon} aggregates tables: {bases}")
        evidence.append(f"Measure dependencies: {', '.join(idx.measure_closure(mcanon)) or '(none)'}")

    for tgt in targets:
        if tgt == src:
            evidence.append(f"'{src}' is the target table itself: filters apply directly.")
            continue
        ok = g.filter_paths(src, tgt, activated)
        every = g.all_paths(src, tgt)
        evidence.append(f"Direction-compatible active paths '{src}' -> '{tgt}': {len(ok)}")
        for p in ok[:3]:
            evidence.append("  ACTIVE PATH: " + _path_text(p))
        blocked = [p for p in every if not all(h.allowed or h.rel.id in activated for h in p)]
        for p in blocked[:3]:
            evidence.append("  BLOCKED PATH: " + _path_text(p))
        if len(ok) >= 2:
            hypotheses.append(_hyp(
                f"Ambiguous propagation: '{src}' reaches '{tgt}' through {len(ok)} paths.", "medium",
                "Multiple active direction-compatible paths were found in the relationship graph.",
                ["Check Model view for ambiguity warnings.", "Deactivate or make single-direction one path."]))
        if not ok:
            inactive = [p for p in blocked if any(not h.rel.is_active for h in p)]
            direction = [p for p in blocked if all(h.rel.is_active for h in p)]
            if inactive:
                rel = next(h.rel for h in inactive[0] if not h.rel.is_active)
                hypotheses.append(_hyp(
                    f"Inactive relationship on the only path from '{src}' to '{tgt}': {rel.label()}.", "high",
                    "Structural evidence: the relationship has isActive=false and no other active path exists"
                    + (" and the measure does not activate it with USERELATIONSHIP." if mcanon else "."),
                    ["Confirm isActive=false in Model view.",
                     f"Create a test measure: CALCULATE([<measure>], USERELATIONSHIP('{rel.from_table}'"
                     f"[{rel.from_column}], '{rel.to_table}'[{rel.to_column}])) and compare.",
                     "Decide whether to activate the relationship or use the USERELATIONSHIP measure in visuals."]))
            if direction:
                hop = next(h for h in direction[0] if not h.allowed)
                hypotheses.append(_hyp(
                    f"Cross-filter direction blocks propagation at '{hop.src}' -> '{hop.dst}'.", "high",
                    f"The path exists, but {hop.rel.label()} is single-direction; filters flow only from the "
                    "one side to the many side.",
                    ["Verify the cross-filter direction in Model view.",
                     f"Test with CROSSFILTER('{hop.rel.from_table}'[{hop.rel.from_column}], "
                     f"'{hop.rel.to_table}'[{hop.rel.to_column}], BOTH) inside a test measure.",
                     "Prefer filtering through a shared dimension instead of enabling bidirectional filters."]))
            if not every:
                hypotheses.append(_hyp(
                    f"No relationship path connects '{src}' and '{tgt}'.", "high",
                    "The relationship graph has no path between these tables, active or inactive.",
                    ["Create a relationship via a shared key or dimension.",
                     "If the table is a parameter table, read it explicitly in DAX (SELECTEDVALUE/TREATAS)."]))
    if mcanon:
        for owner, mod in idx.modifiers_for(mcanon):
            if mod.function in ("ALL", "REMOVEFILTERS", "ALLEXCEPT", "ALLSELECTED"):
                hit = [t for t in mod.targets if src.lower() in t.lower() or
                       any(x.lower() in t.lower() for x in targets)]
                evidence.append(f"Modifier in {owner}: {mod.function}({', '.join(mod.targets)}) [{mod.context}]")
                if hit and mod.function != "ALLEXCEPT":
                    hypotheses.insert(0, _hyp(
                        f"Measure logic removes filters: {owner} uses {mod.function}({', '.join(mod.targets)}).",
                        "high", "Static DAX evidence: the filter modifier targets the selected table or the "
                        "aggregated table, so selections there are ignored by design.",
                        ["Compare the measure with its base measure under the same selection.",
                         "If selections must apply, remove the modifier or use KEEPFILTERS/narrower targets."]))
            elif mod.function == "CROSSFILTER":
                evidence.append(f"Modifier in {owner}: CROSSFILTER({', '.join(mod.targets)}, {mod.direction})")
                if mod.direction == "NONE":
                    hypotheses.insert(0, _hyp(
                        f"{owner} disables a relationship with CROSSFILTER(..., NONE).", "high",
                        "Static DAX evidence of propagation being switched off.",
                        ["Review the CROSSFILTER call and the relationship it targets."]))
    if visual is not None:
        vf = [f for f in visual.fields if f.usage == "filter"]
        evidence.append(f"Visual '{visual.title or visual.name}' ({visual.visual_type}) has {len(vf)} visual-level "
                        "filter(s): " + ", ".join(f"{f.entity}[{f.property}]" for f in vf))
        if vf:
            hypotheses.append(_hyp(
                "Visual-level filters may restrict or widen rows independently of slicers.", "medium",
                "Filters are stored in the visual's filterConfig.",
                ["Open the Filters pane for this visual and review each filter."]))
    if not any(h["confidence"] == "high" for h in hypotheses):
        hypotheses.append(_hyp(
            "Model structure allows propagation; the cause is likely data-level or interaction-level.", "low",
            "No structural blocker was found in the files. Data cannot be inspected statically.",
            ["Check for unmatched keys: rows of the many-side table whose key has no match (shown as (Blank)).",
             "Check key data types, trailing spaces and case differences in Power Query.",
             "Check Format > Edit interactions between the slicer and the visual.",
             "Check bookmarks or sync-slicer settings that may override selections."]))
    for rank, h in enumerate(hypotheses, start=1):
        h["rank"] = rank
    return {"type": "filter-investigation", "from_table": src, "targets": targets, "measure": mcanon,
            "visual": visual.name if visual else None, "evidence": evidence, "hypotheses": hypotheses,
            "note": "Deterministic evidence comes from model files; hypotheses require verification in Power BI."}


def _hyp(text: str, confidence: str, justification: str, steps: list[str]) -> dict[str, Any]:
    return {"hypothesis": text, "confidence": confidence, "justification": justification,
            "verification_steps": steps}


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.security.safety
# ----------------------------------------------------------------------
DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_FILES = 20000

# Diretórios que nunca precisam ser percorridos para a auditoria.
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", ".venv", "venv", "__pycache__", ".pbi", ".idea", ".vs"}

# Padrões de arquivos sensíveis: nunca lidos, apenas contabilizados.
_SENSITIVE_RE = re.compile(
    r"(^\.env(\..*)?$)|(\.(pem|key|pfx|p12|cer|crt|kdbx|ppk)$)|(^id_(rsa|dsa|ecdsa|ed25519))"
    r"|(^(credentials|secrets?)(\..*)?$)|(^localsettings\.json$)|(\.abf$)",
    re.IGNORECASE,
)

# Padrões de redação aplicados a qualquer texto que vá para relatórios.
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(password|pwd|user id|uid|accountkey|sharedaccesskey|client_secret|secret|token|apikey|api_key)"
                r"\s*=\s*[^;\"'\s]+"), r"\1=<redacted>"),
    (re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"), "Bearer <redacted>"),
    (re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*"), "<redacted-jwt>"),
    (re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1<redacted>@"),
    (re.compile(r"(?i)(sig|signature)=[a-z0-9%+/=]{16,}"), r"\1=<redacted>"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE_RE.search(name))


def resolve_root(path: str | os.PathLike[str]) -> Path:
    raw = Path(path).expanduser()
    if not raw.exists():
        raise ForensicsError(f"Path not found: {raw}", exit_code=2)
    if not raw.is_dir():
        raise ForensicsError(f"Not a directory: {raw}", exit_code=2)
    return raw.resolve()


def is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root)
    except (ValueError, OSError):
        return False
    return True


def rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.name


def safe_walk(root: Path, max_files: int = DEFAULT_MAX_FILES,
              exclude_dirs: set[str] | None = None) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    skipped: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept = []
        for d in sorted(dirnames):
            full = current / d
            if d in SKIP_DIRS:
                continue
            if exclude_dirs and d.lower() in exclude_dirs:
                skipped.append(f"excluded-by-option: {rel(root, current)}/{d}")
                continue
            if full.is_symlink() and not is_within(root, full):
                skipped.append(f"symlink-outside-scope: {rel(root, current)}/{d}")
                continue
            if full.is_symlink():
                # Links internos também não são seguidos (evita ciclos).
                skipped.append(f"symlink-not-followed: {rel(root, current)}/{d}")
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in sorted(filenames):
            full = current / name
            if is_sensitive_name(name):
                skipped.append(f"sensitive-file-not-read: {rel(root, full)}")
                continue
            if full.is_symlink() and not is_within(root, full):
                skipped.append(f"symlink-outside-scope: {rel(root, current)}/{name}")
                continue
            files.append(full)
            if len(files) > max_files:
                raise ForensicsError(f"File limit exceeded ({max_files}). Narrow the project path.", 3)
    return files, skipped


def read_text(root: Path, path: Path, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> str:
    if not is_within(root, path):
        raise ForensicsError(f"Refusing to read outside authorized scope: {path.name}", 4)
    if is_sensitive_name(path.name):
        raise ForensicsError(f"Refusing to read sensitive file: {path.name}", 4)
    size = path.stat().st_size
    if size > max_bytes:
        raise ForensicsError(f"File too large ({size} bytes > limit {max_bytes}): {rel(root, path)}", 3)
    data = path.read_bytes()
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        # Alguns exports antigos usam UTF-16 com BOM.
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return data.decode("utf-16")
        raise


def read_json(root: Path, path: Path, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> Any:
    return json.loads(read_text(root, path, max_bytes))


def prepare_output_dir(output: str | os.PathLike[str], forbidden_roots: list[Path]) -> Path:
    out = Path(output).expanduser().resolve()
    for root in forbidden_roots:
        if out == root or is_within(root, out):
            raise ForensicsError(
                "Output directory must be outside the audited project (read-only policy).", 4
            )
    out.mkdir(parents=True, exist_ok=True)
    return out


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.parsers.pbir
# ----------------------------------------------------------------------
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
    try:
        val = visual["visualContainerObjects"]["title"][0]["properties"]["text"]["expr"]["Literal"]["Value"]
    except (KeyError, IndexError, TypeError):
        return None
    val = str(val)
    return val[1:-1].replace("''", "'") if len(val) >= 2 and val[0] == "'" == val[-1] else val


def format_refs(obj: Any, limit: int = 500) -> list[FieldRef]:
    out: list[FieldRef] = []
    stack = [obj]
    while stack and len(out) < limit:
        cur = stack.pop()
        if isinstance(cur, dict):
            if ("Measure" in cur or "Column" in cur) and isinstance(cur.get("Measure", cur.get("Column")), dict):
                fr = field_from_container(cur, None, "format", "format")
                if fr is not None and fr.entity and fr.property:
                    out.append(fr)
                    continue
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return out


def parse_visual_json(data: Any, page: str, path: str) -> Visual:
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
    seen = {(f.kind, f.key()) for f in v.fields}
    for fr in format_refs([vis.get("objects"), vis.get("visualContainerObjects")]):
        if (fr.kind, fr.key()) not in seen:
            seen.add((fr.kind, fr.key()))
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
                page.filters = _filters(pdata.get("filterConfig")) + format_refs(pdata.get("objects"))
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


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.analyzers.visual_rules
# ----------------------------------------------------------------------
CAT_VIS = "Visual dependencies"
_GRID_VISUALS = {"tableEx", "pivotTable", "matrix", "table"}
VISUALS_PER_PAGE_THRESHOLD = 20  # limite orientativo de visuais com dados por página


def resolve_field(idx: SemanticIndex, report: Report, f: FieldRef) -> tuple[str, str]:
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
    bases = sorted(idx.base_tables(measure))
    reached = [b for b in bases if reaches(idx, src, b, measure)]
    blocked = [b for b in bases if b not in reached and idx.graph.table_role(b) != "disconnected"
               and not any(reaches(idx, b, r, measure) for r in reached)]
    return bases, blocked


def dependency_map(report: Report, idx: SemanticIndex | None) -> list[dict[str, Any]]:
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


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.analyzers.stage_visual
# ----------------------------------------------------------------------
def complex_measures(project: Project, indexes: dict[str, SemanticIndex]) -> set[str]:
    refs = [f.object_ref for m in project.models for f in dax_findings(m, indexes[m.path])
            if f.rule_id in ("DAX003", "DAX004", "DAX005")]
    return {x.name.lower() for m in project.models for x in m.all_measures()
            if any(ref.startswith(f"{m.name}/measure/{x.table}/{x.name}/") for ref in refs)}


def visual_stage(project: Project, indexes: dict[str, SemanticIndex]
                 ) -> tuple[list[Finding], list[dict[str, Any]], list[str]]:
    complex_set = complex_measures(project, indexes)
    findings: list[Finding] = []
    limitations: list[str] = []
    dep_map: list[dict[str, Any]] = []
    for r in project.reports:
        model = project.model_for(r)
        idx = indexes.get(model.path) if model else None
        if model is None:
            limitations.append(f"Report '{r.name}': semantic model not available locally "
                               f"({r.dataset_ref or 'no datasetReference'}); field validation skipped.")
        findings.extend(visual_findings(r, model, idx, complex_set))
        dep_map.extend({"report": r.name, **row} for row in dependency_map(r, idx))
    findings.extend(_unused_measures(project, indexes, limitations))
    findings.extend(_unused_columns(project, indexes))
    return findings, dep_map, limitations


def _unused_measures(project: Project, indexes: dict[str, SemanticIndex], limitations: list[str]) -> list[Finding]:
    out = []
    for m in project.models:
        idx = indexes[m.path]
        reps = [r for r in project.reports if r.model_path == m.path]
        blockers = [r.name for r in reps if r.format != "pbir" or r.support != "full" or
                    any(v.limitations for v in r.visuals())]
        if not reps or blockers:
            limitations.append(f"Unused-measure detection skipped for model '{m.name}': "
                               + ("no PBIR report bound by path" if not reps else
                                  f"reports not fully interpretable ({', '.join(blockers)})"))
            continue
        used = set()
        for r in reps:
            fields = [*r.filters, *[x for p in r.pages for x in p.filters], *[x for v in r.visuals() for x in v.fields]]
            for f in fields:
                if f.property and f.property.lower() in idx.measures:
                    used.add(f.property.lower())
        closure = set(used)
        for u in used:
            closure |= {d.lower() for d in idx.measure_closure(u)}
        for x in m.all_measures():
            if x.name.lower() not in closure:
                out.append(Finding(
                    "DAX011", f"Measure not used by any analyzed visual or measure: [{x.name}]", "DAX", "INFO",
                    "potential", [f"Not referenced by visuals/filters in: {', '.join(r.name for r in reps)}",
                                  "Not referenced by any measure that is used"], x.path,
                    f"{m.name}/measure/{x.table}/{x.name}/unused",
                    "Static analysis found no consumer for this measure in the analyzed reports.",
                    "Possibly dead code; other reports connected to the published model may still use it.",
                    "Confirm with workspace lineage / usage metrics before removing.",
                    "Search other reports connected to this model (byConnection) for the measure.",
                    line=x.line))
    return out


def _unused_columns(project: Project, indexes: dict[str, SemanticIndex]) -> list[Finding]:
    out: list[Finding] = []
    for m in project.models:
        idx = indexes[m.path]
        reps = [r for r in project.reports if r.model_path == m.path]
        if not reps or any(r.format != "pbir" or r.support != "full" or any(v.limitations for v in r.visuals())
                           for r in reps):
            continue
        used: set[tuple[str, str]] = set()
        for rel in m.relationships:
            used |= {(rel.from_table.lower(), rel.from_column.lower()), (rel.to_table.lower(), rel.to_column.lower())}
        for ea in [*idx.analyses.values(), *idx.column_analyses]:
            used |= {(t.lower(), c.lower()) for t, c in ea.column_refs}
        for t in m.tables:
            used |= {(t.name.lower(), c.lower()) for c in t.hierarchy_columns}
            used |= {(t.name.lower(), c.sort_by.lower()) for c in t.columns if c.sort_by}
            if t.calc_source:
                used |= {(ref.table.lower(), ref.name.lower()) for ref in analyze_dax(t.calc_source).refs if ref.table}
        for r in reps:
            refs = [*r.filters, *[x for p in r.pages for x in p.filters], *[x for v in r.visuals() for x in v.fields]]
            for f in refs:
                if f.entity and f.property:
                    used.add((f.entity.lower(), f.property.lower()))
        for t in m.tables:
            if t.name.startswith(("LocalDateTable_", "DateTableTemplate_")) or t.is_calculation_group:
                continue
            if t.measures and all(c.is_hidden for c in t.columns) and len(t.columns) <= 1:
                continue  # tabela de medidas (coluna técnica oculta)
            unused = [c.name for c in t.columns if (t.name.lower(), c.name.lower()) not in used]
            if not unused:
                continue
            out.append(Finding(
                "COL001", f"Columns with no detected use in '{t.name}' ({len(unused)} of {len(t.columns)})",
                "Model structure", "INFO", "potential", [", ".join(unused[:30]) + (" …" if len(unused) > 30 else ""),
                "Checked: measures, calculated columns/tables, relationships, hierarchies, sort-by, visuals, filters "
                "and conditional formatting. Not checked: RLS roles, other reports, external tools."],
                t.path, f"{m.name}/table/{t.name}/unused-columns",
                "No reference to these columns was found in the analyzed model and reports.",
                "Unused columns increase model size and refresh time (especially high-cardinality text columns).",
                "Confirm with lineage/usage metrics, then remove them in Power Query.",
                "Search other reports connected to the published model and RLS role filters before removing.",
                line=t.line))
    return out


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.findings.summary
# ----------------------------------------------------------------------
def finalize(findings: list[Finding]) -> dict[str, Any]:
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.id, f)
    ordered = sort_findings(list(unique.values()))
    sev = Counter(f.severity for f in ordered)
    st = Counter(f.status for f in ordered)
    return {"findings": to_jsonable(ordered),
            "severity_breakdown": {s: sev.get(s, 0) for s in SEVERITIES},
            "status_breakdown": {s: st.get(s, 0) for s in STATUSES}}


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.analyzers.audit
# ----------------------------------------------------------------------
def run_audit(project: Project, perf: dict[str, Any] | None = None, perf_source: str = "",
              thresholds: dict[str, float] | None = None) -> dict[str, Any]:
    t0 = datetime.now(UTC)
    indexes = build_indexes(project)
    findings: list[Finding]
    findings, limitations = model_stage(project, indexes)
    limitations = [*BASE_LIMITATIONS, *limitations]
    vis, dep_map, vis_lim = visual_stage(project, indexes)
    findings.extend(vis)
    limitations.extend(vis_lim)
    if perf is not None:
        names = {v.name: f"{r.name}/{p.display_name}/{v.title or v.name}" for r in project.reports
                 for p in r.pages for v in p.visuals}
        findings.extend(performance_findings(perf, perf_source, thresholds, names))
    else:
        limitations.append("No Performance Analyzer log provided: performance section lists static risks only; "
                           "no runtime measurements are available.")
    final = finalize(findings)
    elapsed = (datetime.now(UTC) - t0).total_seconds() * 1000
    return {
        "tool": TOOL_NAME, "version": TOOL_VERSION, "generated_at": t0.isoformat(timespec="seconds"),
        "project": project.root,
        "scope": {"project": project.root, "read_only": True, "performance_log": perf_source or None,
                  "modules": ["discovery", "semantic-model", "dax", "visual-dependencies", "filters"]
                  + (["performance"] if perf else [])},
        "inventory": build_inventory(project, indexes),
        "severity_breakdown": final["severity_breakdown"],
        "status_breakdown": final["status_breakdown"],
        "findings": final["findings"],
        "dependency_map": dep_map,
        "performance": perf,
        "change_impact": None,
        "investigations": [],
        "parse_issues": to_jsonable(collect_issues(project)),
        "limitations": limitations,
        "metrics": {"analysis_ms": round(elapsed, 1), "findings_total": len(final["findings"])},
    }


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.parsers.tmdl
# ----------------------------------------------------------------------
TMDL_OBJECT_TYPES = {
    "database", "model", "table", "column", "measure", "relationship", "partition", "hierarchy",
    "level", "calculationgroup", "calculationitem", "expression", "role", "tablepermission",
    "columnpermission", "annotation", "extendedproperty", "changedproperty", "culture",
    "linguisticmetadata", "perspective", "perspectivetable", "perspectivecolumn",
    "perspectivemeasure", "perspectivehierarchy", "datasource", "querygroup", "variation",
    "formatstringdefinition", "detailrowsdefinition", "refreshpolicy", "member", "translation",
    "alternateof", "function", "calendar", "datacoverage",
}

# Prefixos de funções M que indicam conectores de dados (apenas o nome é guardado).
M_SOURCE_NAMESPACES = {
    "Sql", "Excel", "Csv", "Web", "OData", "SharePoint", "Salesforce", "Odbc", "OleDb", "Oracle",
    "PostgreSQL", "MySQL", "AnalysisServices", "PowerBI", "PowerPlatform", "Lakehouse", "Folder",
    "File", "Snowflake", "GoogleBigQuery", "Databricks", "AzureStorage", "Exchange", "Teradata",
    "Db2", "Access", "Fabric", "AmazonRedshift", "Dataverse", "CommonDataService", "AzureDataExplorer",
    "Kusto", "SapHana", "SapBusinessWarehouse", "Hdfs", "HdInsight", "Spark", "ActiveDirectory",
}
_M_FUNC_RE = re.compile(r"\b([A-Za-z]+)\.([A-Za-z]+)\s*\(")
_IDENT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(.*)$")


def indent_level(line: str) -> int:
    tabs = spaces = 0
    for ch in line:
        if ch == "\t":
            tabs += 1
        elif ch == " ":
            spaces += 1
        else:
            break
    return tabs + spaces // 4


def read_name(text: str, pos: int = 0) -> tuple[str, int]:
    n = len(text)
    while pos < n and text[pos] in " \t":
        pos += 1
    if pos < n and text[pos] == "'":
        pos += 1
        buf = []
        while pos < n:
            ch = text[pos]
            if ch == "'":
                if pos + 1 < n and text[pos + 1] == "'":
                    buf.append("'")
                    pos += 2
                    continue
                return "".join(buf), pos + 1
            buf.append(ch)
            pos += 1
        return "".join(buf), pos
    start = pos
    while pos < n and text[pos] not in " \t=.":
        pos += 1
    # Nomes não-aspeados podem conter '.' apenas em referências qualificadas.
    return text[start:pos], pos


def split_qualified(value: str) -> tuple[str, str] | None:
    value = value.strip()
    table, pos = read_name(value, 0)
    if pos >= len(value) or value[pos] != ".":
        return None
    column, _ = read_name(value, pos + 1)
    if not table or not column:
        return None
    return table, column


def unquote_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('""', '"')
    return value


def detect_m_sources(expression: str) -> list[str]:
    found = []
    for ns, fn in _M_FUNC_RE.findall(expression or ""):
        if ns in M_SOURCE_NAMESPACES:
            name = f"{ns}.{fn}"
            if name not in found:
                found.append(name)
    return found


def _dedent(lines: list[str]) -> list[str]:
    widths = [len(x) - len(x.lstrip(" \t")) for x in lines if x.strip()]
    cut = min(widths) if widths else 0
    return [x[cut:] if x.strip() else "" for x in lines]


@dataclass
class TmdlResult:
    tables: dict[str, Table] = field(default_factory=dict)
    relationships: list[Relationship] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    shared_expressions: list[str] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)


@dataclass
class _Ctx:
    kind: str
    name: str
    indent: int
    obj: object | None = None


class TmdlParser:

    def __init__(self) -> None:
        self.result = TmdlResult()

    # ----------------------------------------------------------------- util
    def _issue(self, path: str, line: int, msg: str, kind: str = "parse-error") -> None:
        self.result.issues.append(ParseIssue(path=path, line=line, message=msg, kind=kind))

    @staticmethod
    def _collect(lines: list[str], start: int, threshold: int) -> tuple[list[str], int]:
        j = start
        buf: list[str] = []
        while j < len(lines):
            cur = lines[j]
            if not cur.strip():
                buf.append("")
                j += 1
                continue
            if indent_level(cur) >= threshold:
                buf.append(cur)
                j += 1
                continue
            break
        while buf and buf[-1] == "":
            buf.pop()
        return _dedent(buf), j

    def _read_expression(self, lines: list[str], i: int, first: str, threshold: int,
                         path: str) -> tuple[str, int]:
        first = first.strip()
        if first.startswith("```"):
            inner = first[3:]
            body: list[str] = [inner] if inner.strip() else []
            j = i + 1
            while j < len(lines):
                if lines[j].strip() == "```":
                    return "\n".join(_dedent(body)).strip("\n"), j + 1
                body.append(lines[j])
                j += 1
            self._issue(path, i + 1, "Unclosed ``` expression delimiter")
            return "\n".join(_dedent(body)).strip("\n"), j
        more, j = self._collect(lines, i + 1, threshold)
        parts = ([first] if first else []) + more
        return "\n".join(parts).strip("\n"), j

    # ---------------------------------------------------------------- parse
    def parse(self, text: str, path: str) -> None:
        lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        stack: list[_Ctx] = []
        i = 0
        while i < len(lines):
            raw = lines[i]
            stripped = raw.strip()
            if not stripped or stripped.startswith("///"):
                i += 1
                continue
            ind = indent_level(raw)
            while stack and stack[-1].indent >= ind:
                stack.pop()
            match = _IDENT_RE.match(stripped)
            if not match:
                self._issue(path, i + 1, f"Unrecognized TMDL line: {stripped[:60]}")
                i += 1
                continue
            keyword, rest = match.group(1), match.group(2)
            kw = keyword.lower()
            rest_s = rest.lstrip()
            parent = stack[-1] if stack else None
            if kw == "ref":
                i += 1
                continue
            if rest_s.startswith(":"):
                self._apply_property(parent, kw, rest_s[1:].strip(), path, i + 1)
                i += 1
                continue
            if rest_s.startswith("="):
                expr, nxt = self._read_expression(lines, i, rest_s[1:], ind + 1, path)
                self._apply_expression(parent, kw, expr)
                i = nxt
                continue
            if kw not in TMDL_OBJECT_TYPES:
                # Propriedade booleana no formato abreviado (ex.: isHidden).
                if not rest_s:
                    self._apply_property(parent, kw, "true", path, i + 1)
                else:
                    self._issue(path, i + 1, f"Unknown TMDL keyword '{keyword}'", "unknown-keyword")
                i += 1
                continue
            name, pos = read_name(rest, 0)
            tail = rest[pos:].strip()
            decl_expr: str | None = None
            nxt = i + 1
            if tail.startswith("="):
                if kw == "partition":
                    decl_expr = tail[1:].strip()  # tipo da partição (m, calculated, entity...)
                else:
                    decl_expr, nxt = self._read_expression(lines, i, tail[1:], ind + 2, path)
            ctx = self._declare(kw, name, decl_expr, parent, path, i + 1)
            stack.append(_Ctx(kw, name, ind, ctx))
            i = nxt

    # --------------------------------------------------------- declarations
    def _declare(self, kw: str, name: str, expr: str | None, parent: _Ctx | None,
                 path: str, line: int) -> object | None:
        res = self.result
        ptable = parent.obj if parent and isinstance(parent.obj, Table) else None
        if kw == "table":
            tbl = res.tables.get(name.lower())
            if tbl is None:
                tbl = Table(name=name, path=path, line=line)
                res.tables[name.lower()] = tbl
            return tbl
        if kw == "column" and ptable is not None:
            col = Column(table=ptable.name, name=name, path=path, line=line,
                         is_calculated=expr is not None, expression=expr)
            ptable.columns.append(col)
            return col
        if kw == "measure" and ptable is not None:
            mea = Measure(table=ptable.name, name=name, expression=expr or "", path=path, line=line)
            ptable.measures.append(mea)
            return mea
        if kw == "relationship":
            rel = Relationship(id=name, from_table="", from_column="", to_table="", to_column="",
                               path=path, line=line)
            res.relationships.append(rel)
            return rel
        if kw == "partition" and ptable is not None:
            kind = (expr or "").split()[0].lower() if expr else "unknown"
            ptable.partition_kinds.append(kind)
            if kind == "calculated":
                ptable.is_calculated = True
            return ("partition", ptable)
        if kw == "hierarchy" and ptable is not None:
            ptable.hierarchies.append(name)
            return ("hierarchy", ptable)
        if kw == "level" and parent and isinstance(parent.obj, tuple) and parent.obj[0] == "hierarchy":
            return ("level", parent.obj[1])
        if kw == "calculationgroup" and ptable is not None:
            ptable.is_calculation_group = True
            return None
        if kw == "expression" and parent is None:
            sources = detect_m_sources(expr or "")
            label = f"{name} ({', '.join(sources)})" if sources else name
            res.shared_expressions.append(label)
            return None
        if kw == "role" and parent is None:
            res.roles.append(name)
            return None
        return None

    # ----------------------------------------------------------- properties
    def _apply_property(self, parent: _Ctx | None, key: str, value: str, path: str, line: int) -> None:
        if parent is None:
            return
        obj = parent.obj
        val = unquote_value(value)
        truthy = val.lower() != "false"
        if isinstance(obj, Relationship):
            if key in ("fromcolumn", "tocolumn"):
                pair = split_qualified(value)
                if pair is None:
                    self._issue(path, line, f"Cannot parse relationship column reference: {value[:60]}")
                    return
                if key == "fromcolumn":
                    obj.from_table, obj.from_column = pair
                else:
                    obj.to_table, obj.to_column = pair
            elif key == "isactive":
                obj.is_active = truthy
            elif key == "crossfilteringbehavior":
                obj.cross_filter = val
            elif key == "fromcardinality":
                obj.from_cardinality = val.lower()
            elif key == "tocardinality":
                obj.to_cardinality = val.lower()
        elif isinstance(obj, Table):
            if key == "ishidden":
                obj.is_hidden = truthy
        elif isinstance(obj, tuple) and obj and obj[0] == "level" and key == "column":
            colname, _ = read_name(value, 0)
            if colname and colname not in obj[1].hierarchy_columns:
                obj[1].hierarchy_columns.append(colname)
        elif isinstance(obj, Column):
            if key == "sortbycolumn":
                obj.sort_by = read_name(value, 0)[0]
            elif key == "datatype":
                obj.data_type = val.lower()
            elif key == "ishidden":
                obj.is_hidden = truthy
        elif isinstance(obj, Measure):
            if key == "formatstring":
                obj.format_string = val
            elif key == "displayfolder":
                obj.display_folder = val
            elif key == "ishidden":
                obj.is_hidden = truthy

    def _apply_expression(self, parent: _Ctx | None, key: str, expr: str) -> None:
        if parent is None:
            return
        obj = parent.obj
        if isinstance(obj, tuple) and obj and obj[0] == "partition" and key == "source":
            table = obj[1]
            if table.is_calculated:
                table.calc_source = expr
            for src in detect_m_sources(expr):
                if src not in table.data_sources:
                    table.data_sources.append(src)
        elif isinstance(obj, Column) and key == "expression":
            obj.expression = expr
            obj.is_calculated = True
        elif isinstance(obj, Measure) and key == "expression":
            obj.expression = expr


def parse_tmdl_texts(files: list[tuple[str, str]]) -> TmdlResult:
    parser = TmdlParser()
    for path, text in files:
        parser.parse(text, path)
    for rel in parser.result.relationships:
        if not (rel.from_table and rel.to_table):
            parser._issue(rel.path, rel.line or 0, f"Relationship '{rel.id}' lacks fromColumn/toColumn")
    return parser.result


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.parsers.model_loader
# ----------------------------------------------------------------------
def _join_expr(value: Any) -> str:
    if isinstance(value, list):
        return "\n".join(str(v) for v in value)
    return str(value) if value is not None else ""


def parse_bim(data: dict[str, Any], path: str) -> tuple[list[Table], list[Relationship], list[str], list[str]]:
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
                sort_by=c.get("sortByColumn"),
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
                for lv in h.get("levels", []) or []:
                    if isinstance(lv, dict) and lv.get("column"):
                        tbl.hierarchy_columns.append(str(lv["column"]))
        for p in t.get("partitions", []) or []:
            src = p.get("source", {}) if isinstance(p, dict) else {}
            kind = str(src.get("type", "unknown")).lower()
            tbl.partition_kinds.append(kind)
            if kind == "calculated":
                tbl.is_calculated = True
                tbl.calc_source = _join_expr(src.get("expression"))
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


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.discovery.detector
# ----------------------------------------------------------------------
def discover(path: str | Path, max_bytes: int = DEFAULT_MAX_FILE_BYTES,
             max_files: int = DEFAULT_MAX_FILES, exclude_dirs: set[str] | None = None) -> Project:
    root = resolve_root(path)
    files, skipped = safe_walk(root, max_files, {d.lower() for d in exclude_dirs or set()})
    project = Project(root=root.name, skipped=skipped)
    report_dirs: set[Path] = set()
    model_dirs: set[Path] = set()
    for f in files:
        low = f.name.lower()
        if low.endswith(".pbip"):
            project.pbip_files.append(rel(root, f))
            try:
                meta = read_json(root, f, max_bytes)
                for art in (meta.get("artifacts", []) if isinstance(meta, dict) else []) or []:
                    rpath = ((art or {}).get("report") or {}).get("path")
                    if rpath and not (f.parent / rpath).resolve().is_dir():
                        project.issues.append(ParseIssue(rel(root, f), f"Referenced report folder not "
                                                         f"found: {rpath}", kind="structure"))
            except (json.JSONDecodeError, UnicodeDecodeError, ForensicsError) as exc:
                project.issues.append(ParseIssue(rel(root, f), f"Invalid .pbip file: {exc}"))
        elif low == "definition.pbir":
            report_dirs.add(f.parent)
        elif low == "definition.pbism" or (low == "model.bim" and f.parent.name.endswith(".SemanticModel")):
            model_dirs.add(f.parent)
        elif low.endswith(".pbix") or low.endswith(".pbit"):
            project.issues.append(ParseIssue(rel(root, f), "Binary PBIX/PBIT is not supported; save as "
                                             "PBIP (File > Save as > Power BI project)", kind="unsupported"))
    # Pastas *.Report / *.SemanticModel sem arquivo de definição também são sinalizadas.
    for f in files:
        for parent in f.parents:
            if parent == root.parent:
                break
            if parent.name.endswith(".Report") and parent not in report_dirs:
                report_dirs.add(parent)
            if parent.name.endswith(".SemanticModel") and parent not in model_dirs:
                model_dirs.add(parent)
    for mdir in sorted(model_dirs):
        project.models.append(load_semantic_model(root, mdir, max_bytes))
    for rdir in sorted(report_dirs):
        project.reports.append(load_report(root, rdir, max_bytes))
    return project


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.reporting.insights
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.reporting.html_report
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.reporting.render
# ----------------------------------------------------------------------
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
    if sev:  # notas, resumo em linguagem simples e ações rápidas (somente auditoria completa)
        ins = compute_insights(doc, lang)
        il = INS_LABELS.get(lang, INS_LABELS["en"])
        sc = ins["scores"]
        pt = lang == "pt-BR"
        areas = [f"{il[a['key']]}: {'–' if a['score'] is None else a['score']} ({il[a['grade']]})"
                 for a in sc["areas"]]
        b.append(("p", f"**{'Nota de saúde' if pt else 'Health score'}: {sc['overall']}/100 "
                       f"({il[sc['grade']]})** · " + " · ".join(areas) + f". _{sc['formula']}_"))
        b.append(("h3", "Em palavras simples" if pt else "In plain words"))
        b.append(("ul", ins["narrative"]))
        b.append(("h3", "O que fazer primeiro" if pt else "What to do first"))
        b.append(("ol", [f"**{w['title']}** — {il[w['effort']]}, {w['severity']}, {w['count']}× (`{w['rule_id']}`): "
                         f"{w['recommendation']}" for w in ins["quick_wins"]]))
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


def render(doc: dict[str, Any], fmt: str, lang: str = "en") -> str:
    if fmt == "json":
        return json.dumps(doc, indent=2, ensure_ascii=False)
    blocks = build_blocks(doc, lang)
    if fmt == "markdown":
        return to_markdown(blocks)
    if fmt == "html":
        return to_html_report(doc, lang)
    raise ValueError(f"Unknown format: {fmt}")


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.automation
# ----------------------------------------------------------------------
# Pastas tipicamente usadas para cópias antigas do projeto (evitam modelos duplicados).
DEFAULT_EXCLUDES = {"backup", "backups", "bkp", "_backup", "old", "archive", "_archive", ".agents"}
_PERF_HINTS = ("performance", "powerbiperformancedata", "perfanalyzer")


def default_output(root: Path) -> Path:
    return root.parent / f"{root.name}-forensics"


def find_performance_log(root: Path, max_bytes: int, max_depth: int = 2) -> Path | None:
    candidates = []
    for p in root.rglob("*.json"):
        if len(p.relative_to(root).parts) > max_depth + 1 or p.is_symlink() or not is_within(root, p):
            continue
        if any(h in p.name.lower() for h in _PERF_HINTS):
            candidates.append(p)
    for p in sorted(candidates, key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            data = read_json(root, p, max_bytes)
            if isinstance(data, dict) and isinstance(data.get("events"), list):
                return p
        except (json.JSONDecodeError, UnicodeDecodeError, ForensicsError):
            continue
    return None


def run_full(project: str | Path, performance: str | Path | None = None, output: str | Path | None = None,
             lang: str = "en", excludes: set[str] | None = None, max_bytes: int = 25 * 1024 * 1024,
             auto_perf: bool = True) -> tuple[dict[str, Any], dict[str, Path]]:
    root = resolve_root(project)
    proj = discover(root, max_bytes=max_bytes, exclude_dirs=DEFAULT_EXCLUDES if excludes is None else excludes)
    perf_path: Path | None = None
    if performance:
        perf_path = Path(performance).expanduser().resolve()
        if not perf_path.is_file():
            raise ForensicsError(f"Performance log not found: {perf_path}", 2)
    elif auto_perf:
        perf_path = find_performance_log(root, max_bytes)
    perf = None
    if perf_path is not None:
        try:
            perf = parse_performance(read_json(perf_path.parent, perf_path, max_bytes))
        except json.JSONDecodeError as exc:
            raise ForensicsError(f"Performance log is not valid JSON: {exc}", 5) from exc
    doc = run_audit(proj, perf, perf_path.name if perf_path else "")
    excluded = [s for s in proj.skipped if s.startswith("excluded-by-option")]
    if excluded:
        doc["limitations"].append(f"Folders excluded from the scan: {', '.join(x.split(': ', 1)[1] for x in excluded)}")
    if len(proj.models) > 1:
        doc["limitations"].append(f"{len(proj.models)} semantic models found; check for copies of the same model "
                                  "(use --exclude for backup folders).")
    out = prepare_output_dir(output or default_output(root), [root])
    files = {"html": out / "audit-report.html", "markdown": out / "audit-report.md", "json": out / "findings.json"}
    for fmt, path in files.items():
        path.write_text(render(doc, fmt, lang), encoding="utf-8", newline="\n")
    return doc, files


def console_summary(doc: dict[str, Any], files: dict[str, Path], top: int = 5) -> str:
    sev = doc["severity_breakdown"]
    lines = [f"Project: {doc['project']}  |  findings: {sum(sev.values())} "
             + " ".join(f"{k}={v}" for k, v in sev.items() if v),
             f"Performance log: {doc['scope'].get('performance_log') or 'not found (static risks only)'}"]
    hi = [f for f in doc["findings"] if f["severity"] in ("CRITICAL", "HIGH")][:top]
    for f in hi:
        lines.append(f"  [{f['severity']}/{f['status']}] {f['title']}")
    lines.append(f"Report: {files['html']}")
    return "\n".join(lines)


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.entrypoints.common
# ----------------------------------------------------------------------
def skill_parser(description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--output", help="output directory (outside the audited project); default: print JSON")
    p.add_argument("--max-file-mb", type=float, default=25.0, help="per-file size limit in MB")
    return p


def skill_header(script: str, project: str | None) -> dict[str, Any]:
    return {"tool": TOOL_NAME, "version": TOOL_VERSION, "script": script, "project": project,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds")}


def skill_emit(doc: dict[str, Any], output: str | None, filename: str, roots: list[Path]) -> None:
    text = json.dumps(doc, indent=2, ensure_ascii=False)
    if output:
        out = prepare_output_dir(output, roots)
        (out / filename).write_text(text, encoding="utf-8", newline="\n")
        counts = doc.get("severity_breakdown") or {}
        summary = ", ".join(f"{k}={v}" for k, v in counts.items())
        print(f"wrote {filename}" + (f" (findings: {summary})" if summary else ""), file=sys.stderr)
    else:
        print(text)


def skill_run(fn: Callable[[list[str] | None], int], argv: list[str] | None = None) -> int:
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    try:
        return fn(argv)
    except ForensicsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except (OSError, UnicodeDecodeError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # erro inesperado: sem traceback para o usuário final
        print(f"error: internal error ({type(exc).__name__})", file=sys.stderr)
        return 10


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.entrypoints.ep_full_audit
# ----------------------------------------------------------------------
def full_audit_main(argv: list[str] | None = None) -> int:
    p = skill_parser("One-shot audit: inventory, model, DAX, visuals, performance (auto-detected) and report.")
    p.add_argument("--project", required=True, help="PBIP project folder authorized for reading")
    p.add_argument("--performance", help="Performance Analyzer export; auto-detected inside the project if omitted")
    p.add_argument("--lang", choices=["en", "pt-BR"], default="en")
    p.add_argument("--exclude", action="append", default=None,
                   help=f"folder name to skip (repeatable); default: {', '.join(sorted(DEFAULT_EXCLUDES))}")
    p.add_argument("--no-default-excludes", action="store_true", help="scan every folder")
    a = p.parse_args(argv)
    excludes = set() if a.no_default_excludes else set(DEFAULT_EXCLUDES)
    excludes |= {x.lower() for x in a.exclude or []}
    doc, files = run_full(a.project, a.performance, a.output, a.lang, excludes, int(a.max_file_mb * 1024 * 1024))
    print(console_summary(doc, files), file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    return skill_run(full_audit_main, argv)


if __name__ == "__main__":
    raise SystemExit(main())
