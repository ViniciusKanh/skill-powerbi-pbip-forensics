#!/usr/bin/env python3
"""Power BI PBIP Forensics — pbip_diff.py (v1.0.0, Vinicius de Souza Santos).

Standalone, read-only script generated from the modular engine (src/pbip_forensics).
Requires only the Python 3.11+ standard library. Run with --help for usage.
Never modifies the analyzed project; writes only to --output (outside the project).
"""

# Arquivo gerado por tools/build_skill.py — não editar manualmente.
# Módulos incluídos: models, graph.model_graph, parsers.dax, analyzers.semantic, analyzers.diff, parsers.tmdl, security.safety, parsers.model_loader, parsers.pbir, discovery.detector, entrypoints.common, entrypoints.ep_diff

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
from collections import defaultdict
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
            elif call.name in _MODIFIER_FUNCS and call.args:
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
# módulo de origem: pbip_forensics.analyzers.diff
# ----------------------------------------------------------------------
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
            return None
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
        elif isinstance(obj, Column):
            if key == "datatype":
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


def safe_walk(root: Path, max_files: int = DEFAULT_MAX_FILES) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    skipped: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept = []
        for d in sorted(dirnames):
            full = current / d
            if d in SKIP_DIRS:
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


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.discovery.detector
# ----------------------------------------------------------------------
def discover(path: str | Path, max_bytes: int = DEFAULT_MAX_FILE_BYTES,
             max_files: int = DEFAULT_MAX_FILES) -> Project:
    root = resolve_root(path)
    files, skipped = safe_walk(root, max_files)
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
# módulo de origem: pbip_forensics.entrypoints.ep_diff
# ----------------------------------------------------------------------
def diff_main(argv: list[str] | None = None) -> int:
    p = skill_parser("Compare two PBIP project versions and estimate change impact.")
    p.add_argument("--before", required=True, help="previous version folder")
    p.add_argument("--after", required=True, help="current version folder")
    a = p.parse_args(argv)
    r1, r2 = resolve_root(a.before), resolve_root(a.after)
    limit = int(a.max_file_mb * 1024 * 1024)
    before, after = discover(r1, max_bytes=limit), discover(r2, max_bytes=limit)
    impact = diff_projects(before, after)
    doc = {**skill_header("diff", f"{before.root} -> {after.root}"), "change_impact": impact, "findings": [],
           "limitations": [impact["note"]]}
    skill_emit(doc, a.output, "diff.json", [r1, r2])
    return 0


def main(argv: list[str] | None = None) -> int:
    return skill_run(diff_main, argv)


if __name__ == "__main__":
    raise SystemExit(main())
