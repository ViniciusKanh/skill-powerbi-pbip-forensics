"""Índice semântico: resolve referências DAX contra o modelo e monta o grafo
de dependências entre medidas, colunas e tabelas.

Tudo é análise estática: nenhuma expressão é avaliada.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pbip_forensics.graph.model_graph import ModelGraph, strongly_connected
from pbip_forensics.models import Column, Measure, Project, Relationship, SemanticModel
from pbip_forensics.parsers.dax import CALC_FUNCS, DAX_KEYWORDS, FILTER_REMOVERS, DaxInfo, analyze_dax

# Funções que criam colunas implícitas ([Value], [Date]...) em tabelas temporárias.
_IMPLICIT_COLUMN_FUNCS = {"GENERATESERIES", "CALENDAR", "CALENDARAUTO", "DATATABLE", "ROW"}
_MODIFIER_FUNCS = FILTER_REMOVERS | {"USERELATIONSHIP", "CROSSFILTER", "KEEPFILTERS", "TREATAS"}


@dataclass
class Modifier:
    """Modificação de contexto de filtro detectada em uma expressão."""

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
    """Resolve referências e oferece consultas de dependência."""

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
        """Faixas de tokens que são argumentos de filtro (não agregação base)."""
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
        """Medidas das quais `name` depende (transitivo), sem incluir a própria."""
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
        """Medidas que dependem de `name` (transitivo)."""
        out = []
        for low, ea in self.analyses.items():
            if low != name.lower() and name.lower() in {d.lower() for d in self.measure_closure(ea.name)}:
                out.append(ea.name)
        return sorted(out, key=str.lower)

    def base_tables(self, name: str) -> set[str]:
        """Tabelas agregadas pela medida, incluindo dependências."""
        tables: set[str] = set()
        for m in [name, *self.measure_closure(name)]:
            ea = self.analyses.get(m.lower())
            if ea:
                tables |= ea.base_tables
        return tables

    def modifiers_for(self, name: str) -> list[tuple[str, Modifier]]:
        """Modificadores de contexto da medida e de suas dependências."""
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
    """Um índice semântico por modelo (chave: caminho relativo do modelo)."""
    return {m.path: SemanticIndex(m) for m in project.models}
