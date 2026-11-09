"""Tokenizador e analisador estrutural de expressões DAX (sem execução).

O tokenizador respeita:
- strings "..." com escape "" ;
- comentários //, -- e /* ... */ ;
- nomes de tabela entre aspas simples '...' com escape '' ;
- referências entre colchetes [...] com escape ]] ;
- números, identificadores (inclusive funções com ponto, ex.: PERCENTILEX.INC),
  parênteses, vírgulas/ponto e vírgula e operadores.

Sobre os tokens significativos é construída uma árvore de chamadas de funções
(nome, argumentos, chamada pai, índice do argumento no pai). Isso permite regras
contextuais (ex.: FILTER usado como argumento de filtro de CALCULATE) sem tentar
reproduzir o mecanismo tabular. Nenhum resultado numérico é calculado.
"""

from __future__ import annotations

from dataclasses import dataclass, field

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
        """Lista (índice da chamada ancestral, argumento do filho) até a raiz."""
        out = []
        cur = self.calls[call_idx]
        while cur.parent is not None:
            parent_idx = cur.parent
            out.append((parent_idx, cur.parent_arg))
            cur = self.calls[parent_idx]
        return out


def tokenize(text: str) -> tuple[list[Token], list[str]]:
    """Converte DAX em tokens (inclui espaços e comentários)."""
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
    """Constrói tokens significativos, chamadas e referências de uma expressão."""
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
    """Sequência de tokens sem espaços/comentários (para comparação entre versões)."""
    toks, _ = tokenize(expression or "")
    return [f"{t.kind}:{t.value.upper() if t.kind == 'IDENT' else t.value}" for t in toks
            if t.kind not in ("WS", "COMMENT")]
