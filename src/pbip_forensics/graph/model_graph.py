"""Grafos de relacionamentos (propagação de filtros) e de dependências.

Convenções de propagação (semântica documentada do Power BI/TOM):
- Relacionamento many(from) -> one(to) com `oneDirection`: o filtro flui da
  tabela do lado "one" (toTable) para a do lado "many" (fromTable);
- `bothDirections`: o filtro flui nos dois sentidos;
- one-to-one: tratado como bidirecional (comportamento do Power BI Desktop);
- `automatic`: tratado como `oneDirection` (registrado como suposição);
- relacionamentos inativos não propagam, exceto quando ativados por
  USERELATIONSHIP em uma medida específica.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from pbip_forensics.models import Relationship, SemanticModel


@dataclass(frozen=True)
class Hop:
    """Um passo de propagação: src -> dst através de `rel`."""

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
    """Grafo de relacionamentos de um modelo semântico."""

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
        """Todos os passos (permitidos ou não) partindo de `table`."""
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
        """Caminhos dirigidos pelos quais um filtro em `src` alcança `dst`."""
        return self._paths(src, dst, max_len, limit, only_allowed=True, activated=activated)

    def all_paths(self, src: str, dst: str, max_len: int = 6, limit: int = 20) -> list[list[Hop]]:
        """Caminhos ignorando direção/estado (para explicar bloqueios)."""
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
        """Componentes conexos (grafo não-dirigido)."""
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
        """Base de ciclos entre relacionamentos ativos (árvore geradora)."""
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
        """Classificação estrutural: fact, dimension, bridge ou disconnected."""
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
        """Localiza o relacionamento que liga as colunas informadas (qualquer ordem)."""
        a = (t1.lower(), c1.lower())
        b = (t2.lower(), c2.lower())
        for r in self.model.relationships:
            x = (r.from_table.lower(), r.from_column.lower())
            y = (r.to_table.lower(), r.to_column.lower())
            if (x, y) in ((a, b), (b, a)):
                return r
        return None


def strongly_connected(adj: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan iterativo: retorna componentes fortemente conexos com ciclo."""
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
