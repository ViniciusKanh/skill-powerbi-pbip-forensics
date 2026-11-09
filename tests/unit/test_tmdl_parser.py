"""Testes do parser TMDL, incluindo expressões multilinha e nomes especiais."""

from pbip_forensics.discovery.detector import discover
from pbip_forensics.parsers.tmdl import indent_level, parse_tmdl_texts, read_name, split_qualified
from tests.conftest import FIXTURES


def test_read_name_quoted_and_plain():
    assert read_name("'My ''Table'' X' = 1") == ("My 'Table' X", 16)
    assert read_name("Sales-Partition1 = m")[0] == "Sales-Partition1"


def test_split_qualified_variants():
    assert split_qualified("Sales.'Product Key'") == ("Sales", "Product Key")
    assert split_qualified("'Sales.Data'.Amount") == ("Sales.Data", "Amount")
    assert split_qualified("NoDot") is None


def test_indent_level_tabs_and_spaces():
    assert indent_level("\t\tx") == 2
    assert indent_level("        x") == 2


def test_multiline_backticks_descriptions_crlf():
    model = discover(FIXTURES / "multiline_tmdl").models[0]
    ms = {m.name: m for m in model.all_measures()}
    assert ms["Multi Line"].expression == "VAR x =\n\tSUM(Facts[Value])\n\nRETURN\n\tx * 2"
    assert ms["Multi Line"].format_string == "0.00"
    assert ms["Backticks"].expression.startswith("// comentário")
    assert '""aspas""' in ms["Backticks"].expression
    assert ms["Same Line"].display_folder == ' Folder "Q" '
    assert not [i for i in model.issues if i.kind == "parse-error"]


def test_relationship_properties_and_partial_tables():
    res = parse_tmdl_texts([
        ("a.tmdl", "table T\n\tcolumn A\n\t\tdataType: int64\n"),
        ("b.tmdl", "table T\n\tmeasure M = SUM(T[A])\n"),
        ("r.tmdl", "relationship x\n\tisActive: false\n\tcrossFilteringBehavior: bothDirections\n"
                   "\tfromCardinality: many\n\ttoCardinality: many\n\tfromColumn: T.A\n\ttoColumn: 'U X'.B\n"),
    ])
    t = res.tables["t"]
    assert [c.name for c in t.columns] == ["A"] and [m.name for m in t.measures] == ["M"]
    r = res.relationships[0]
    assert (r.is_active, r.cross_filter, r.to_table, r.to_cardinality) == (False, "bothDirections", "U X", "many")


def test_unknown_keyword_does_not_crash():
    res = parse_tmdl_texts([("x.tmdl", "table T\n\tfuturePropertyFlag\n\tweird stuff here\n")])
    assert "t" in res.tables
    assert any(i.kind == "unknown-keyword" for i in res.issues)


def test_relationship_without_columns_is_issue():
    res = parse_tmdl_texts([("r.tmdl", "relationship broken\n\tisActive: true\n")])
    assert any("lacks fromColumn" in i.message for i in res.issues)


def test_special_identifiers_unicode():
    model = discover(FIXTURES / "special_identifiers").models[0]
    assert model.table("Vendas Líquidas") is not None
    names = [m.name for m in model.all_measures()]
    assert "Cliente's Média" in names and "Receita (R$) – Total" in names
    assert model.relationships[0].from_column == "Código Cliente"
