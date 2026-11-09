"""Testes do tokenizador e da árvore de chamadas DAX."""

from pbip_forensics.parsers.dax import analyze_dax, normalized_tokens, tokenize


def kinds(text: str) -> list[tuple[str, str]]:
    toks, _ = tokenize(text)
    return [(t.kind, t.value) for t in toks if t.kind != "WS"]


def test_strings_with_escaped_quotes_and_brackets_are_not_references():
    info = analyze_dax('"a ""quoted"" [NotRef]" & [Real]')
    assert [r.name for r in info.refs] == ["Real"]
    assert 'a "quoted" [NotRef]' in info.strings


def test_comments_are_ignored_for_references():
    info = analyze_dax("// [Fake1]\n-- [Fake2]\n/* [Fake3] */ [Real]")
    assert [r.name for r in info.refs] == ["Real"]


def test_quoted_table_with_escaped_quote_and_bracket_escape():
    info = analyze_dax("SUM('Customer''s Table'[Amount]]X])")
    assert info.refs[0].table == "Customer's Table"
    assert info.refs[0].name == "Amount]X"


def test_function_names_with_dots_and_call_tree():
    info = analyze_dax("CALCULATE([M], FILTER(ALL(T), PERCENTILEX.INC(T, T[x], 0.5) > 1))")
    names = [c.name for c in info.calls]
    assert names == ["CALCULATE", "FILTER", "ALL", "PERCENTILEX.INC"]
    filt = info.calls[1]
    assert filt.parent == 0 and filt.parent_arg == 1
    assert info.calls[2].parent == 1 and info.calls[2].parent_arg == 0
    assert len(info.calls[0].args) == 2


def test_var_return_keywords_not_table_qualifiers():
    info = analyze_dax("VAR x = 1 RETURN [Measure]")
    assert info.refs[0].table is None
    assert "x" in info.variables


def test_unterminated_string_is_reported():
    info = analyze_dax('"open string')
    assert info.errors


def test_unbalanced_parentheses_reported():
    assert analyze_dax("SUM(T[x]").errors
    assert analyze_dax("SUM(T[x]))").errors


def test_semicolon_separator_is_treated_as_comma():
    info = analyze_dax("DIVIDE([a]; [b])")
    assert len(info.calls[0].args) == 2


def test_normalized_tokens_ignore_whitespace_and_comments():
    assert normalized_tokens("SUM ( T[x] ) // c") == normalized_tokens("sum(T[x])")
    assert normalized_tokens("SUM(T[x])") != normalized_tokens("SUM(T[y])")


def test_numbers_and_operators():
    assert ("NUMBER", "1.5e3") in kinds("1.5e3 + 2")
    assert ("OP", "<>") in kinds("a <> b")
