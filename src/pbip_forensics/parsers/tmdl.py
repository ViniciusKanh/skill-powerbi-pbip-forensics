"""Parser TMDL (Tabular Model Definition Language) baseado em indentação.

Implementa as regras documentadas em
https://learn.microsoft.com/analysis-services/tmdl/tmdl-overview :
- indentação por TAB define a hierarquia (espaços: 4 = 1 nível, tolerado);
- `chave: valor` para propriedades não-expressão;
- `chave = expressão` e `objeto Nome = expressão` para expressões;
- expressões multilinha começam na linha seguinte, mais indentadas;
- delimitadores ``` preservam a expressão literalmente;
- nomes entre aspas simples, com '' como escape;
- `///` descrições e `ref` (referências de ordenação) são ignorados.

O parser é tolerante: linhas não reconhecidas viram ParseIssue, nunca exceção.
Nenhuma expressão DAX/M é executada.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pbip_forensics.models import Column, Measure, ParseIssue, Relationship, Table

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
    """Calcula o nível de indentação (TAB = 1 nível; 4 espaços = 1 nível)."""
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
    """Lê um nome TMDL (entre aspas simples ou não) a partir de `pos`."""
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
    """Divide `Tabela.Coluna` / `'Tabela X'.'Coluna Y'` em (tabela, coluna)."""
    value = value.strip()
    table, pos = read_name(value, 0)
    if pos >= len(value) or value[pos] != ".":
        return None
    column, _ = read_name(value, pos + 1)
    if not table or not column:
        return None
    return table, column


def unquote_value(value: str) -> str:
    """Remove aspas duplas opcionais de valores textuais ("" vira ")."""
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('""', '"')
    return value


def detect_m_sources(expression: str) -> list[str]:
    """Extrai somente nomes de conectores M (sem argumentos, por privacidade)."""
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
    """Parser incremental: pode receber vários arquivos (declarações parciais)."""

    def __init__(self) -> None:
        self.result = TmdlResult()

    # ----------------------------------------------------------------- util
    def _issue(self, path: str, line: int, msg: str, kind: str = "parse-error") -> None:
        self.result.issues.append(ParseIssue(path=path, line=line, message=msg, kind=kind))

    @staticmethod
    def _collect(lines: list[str], start: int, threshold: int) -> tuple[list[str], int]:
        """Coleta linhas de continuação de expressão (indentação >= threshold)."""
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
        """Lê expressão de linha única, multilinha ou delimitada por ```."""
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
        """Analisa um arquivo .tmdl e acumula os objetos encontrados."""
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
    """Analisa uma lista de (caminho_relativo, texto) e retorna o resultado agregado."""
    parser = TmdlParser()
    for path, text in files:
        parser.parse(text, path)
    for rel in parser.result.relationships:
        if not (rel.from_table and rel.to_table):
            parser._issue(rel.path, rel.line or 0, f"Relationship '{rel.id}' lacks fromColumn/toColumn")
    return parser.result
