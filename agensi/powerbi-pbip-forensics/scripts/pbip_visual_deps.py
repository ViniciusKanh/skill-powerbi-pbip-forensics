#!/usr/bin/env python3
"""Power BI PBIP Forensics — pbip_visual_deps.py (v1.0.0, Vinicius de Souza Santos).

Standalone, read-only script generated from the modular engine (src/pbip_forensics).
Requires only the Python 3.11+ standard library. Run with --help for usage.
Never modifies the analyzed project; writes only to --output (outside the project).
"""

# Arquivo gerado por tools/build_skill.py — não editar manualmente.
# Módulos incluídos: models, graph.model_graph, parsers.dax, analyzers.semantic, analyzers.filters, analyzers.dax_rules, security.safety, parsers.pbir, analyzers.visual_rules, analyzers.stage_visual, parsers.tmdl, parsers.model_loader, discovery.detector, entrypoints.common, findings.summary, entrypoints.ep_visual_deps

from __future__ import annotations

import sys

if sys.version_info < (3, 11):  # verificação antes de qualquer import dependente de versão
    sys.stderr.write("error: Python 3.11 or newer is required (found %d.%d)\n" % sys.version_info[:2])
    raise SystemExit(2)

import argparse
import contextlib
import hashlib
import json
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
# módulo de origem: pbip_forensics.entrypoints.ep_visual_deps
# ----------------------------------------------------------------------
def visual_deps_main(argv: list[str] | None = None) -> int:
    p = skill_parser("Map Page -> Visual -> Field -> Table, validate bindings and investigate filter propagation.")
    p.add_argument("--project", required=True, help="PBIP project folder authorized for reading")
    p.add_argument("--from-table", help="table where a selection/filter is applied (investigation mode)")
    p.add_argument("--to-table", help="table expected to be filtered")
    p.add_argument("--measure", help="measure expected to react to the filter")
    p.add_argument("--visual", help="visual name or title whose filters should be included")
    a = p.parse_args(argv)
    root = resolve_root(a.project)
    project = discover(root, max_bytes=int(a.max_file_mb * 1024 * 1024))
    indexes = build_indexes(project)
    findings, dep_map, limitations = visual_stage(project, indexes)
    investigations: list[dict[str, Any]] = []
    if a.from_table:
        if not project.models:
            raise ForensicsError("No semantic model found for investigation", 2)
        visual = None
        if a.visual:
            visual = next((v for r in project.reports for v in r.visuals()
                           if a.visual.lower() in (v.name.lower(), (v.title or "").lower())), None)
            if visual is None:
                raise ForensicsError(f"Visual not found: {a.visual}", 2)
        investigations.append(investigate_filter(indexes[project.models[0].path], a.from_table, a.to_table,
                                                 a.measure, visual))
    doc = {**skill_header("visual_deps", project.root), **finalize(findings), "dependency_map": dep_map,
           "investigations": investigations, "limitations": limitations}
    skill_emit(doc, a.output, "visual_deps.json", [root])
    return 0


def main(argv: list[str] | None = None) -> int:
    return skill_run(visual_deps_main, argv)


if __name__ == "__main__":
    raise SystemExit(main())
