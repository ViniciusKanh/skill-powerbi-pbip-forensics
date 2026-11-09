"""Cenários de diagnóstico (positivos e negativos) sobre fixtures sintéticas."""

from pbip_forensics.analyzers.filters import investigate_filter
from pbip_forensics.analyzers.semantic import SemanticIndex
from pbip_forensics.discovery.detector import discover
from tests.conftest import FIXTURES, audit, rules


# ----------------------------------------------------------------- cenários negativos
def test_simple_valid_project_has_no_false_positives():
    doc = audit(FIXTURES / "simple_valid")
    bad = [f for f in doc["findings"] if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
    assert bad == []
    for rid in ("MOD002", "MOD003", "MOD006", "MOD008", "DAX001", "VIS001", "VIS002", "VIS005", "VIS006"):
        assert rules(doc, rid) == [], rid
    inv = doc["inventory"]["counts"]
    assert inv["tables"] == 2 and inv["measures"] == 1 and inv["visuals"] == 2


def test_loop_without_bidirectional_is_not_ambiguous():
    doc = audit(FIXTURES / "loop_not_ambiguous")
    loop = rules(doc, "MOD006")
    assert loop and all(f["severity"] == "INFO" for f in loop)


def test_valid_dax_patterns_not_flagged_as_missing():
    doc = audit(FIXTURES / "dax_patterns")
    missing = {f["title"] for f in rules(doc, "DAX001")}
    assert not any("Local Columns" in t or "Series" in t or "Good Column Filter" in t for t in missing)
    assert not [f for f in rules(doc, "DAX003") if "Good Column Filter" in f["title"]]


# ----------------------------------------------------------------- cenários positivos
def test_inactive_relationship_detected_and_unactivated():
    doc = audit(FIXTURES / "inactive_relationship")
    f = rules(doc, "MOD002")
    assert len(f) == 1 and f[0]["severity"] == "LOW" and f[0]["status"] == "potential"
    # o gráfico por cliente não alcança Sales pelo relacionamento inativo
    assert rules(doc, "VIS005")


def test_ambiguous_path_detected():
    doc = audit(FIXTURES / "ambiguous_path")
    amb = [f for f in rules(doc, "MOD006") if f["severity"] == "HIGH"]
    assert amb and "Budget" in amb[0]["title"]
    assert rules(doc, "MOD003")


def test_disconnected_dimension():
    doc = audit(FIXTURES / "disconnected_dimension")
    f = rules(doc, "MOD008")
    assert len(f) == 1 and "Region" in f[0]["title"]


def test_missing_references_confirmed():
    doc = audit(FIXTURES / "dax_patterns")
    titles = " ".join(f["title"] for f in rules(doc, "DAX001", "confirmed"))
    assert "[Does Not Exist]" in titles and "'Sales'[Nope]" in titles and "'Ghost'[Col]" in titles


def test_costly_and_context_patterns():
    doc = audit(FIXTURES / "dax_patterns")
    assert [f for f in rules(doc, "DAX003") if "Costly" in f["title"]]
    assert [f for f in rules(doc, "DAX004") if "Nested" in f["title"]]
    ctx = [f for f in rules(doc, "DAX006") if "Ignore Customer" in f["title"]]
    assert ctx and "ALL('Customer')" in ctx[0]["evidence"][0]
    cyc = rules(doc, "DAX002", "confirmed")
    assert cyc and "Cycle1" in cyc[0]["title"]


def test_visual_issues_missing_custom_and_malformed():
    doc = audit(FIXTURES / "visual_issues")
    assert [f for f in rules(doc, "VIS002", "confirmed") if "Revenue Old" in f["title"]]
    assert [f for f in rules(doc, "VIS001", "confirmed") if "Ghost" in f["title"]]
    assert [f for f in rules(doc, "VIS003", "inconclusive") if "myCustomVisual" in f["title"]]
    assert rules(doc, "PRS001", "confirmed")  # visual.json malformado
    vis = {v["name"]: v for p in doc["inventory"]["reports"][0]["pages"] for v in p["visuals"]}
    assert vis["broken"]["type"] == "unparsed"


def test_legacy_and_tmsl_support():
    project = discover(FIXTURES / "legacy_pbir")
    rep, model = project.reports[0], project.models[0]
    assert rep.format == "pbir-legacy" and rep.support == "limited"
    assert rep.pages[0].visuals[0].fields[0].entity == "Sales"
    assert model.format == "tmsl" and model.all_measures()[0].expression == "SUM(\nSales[Amount])"
    assert model.tables[0].data_sources == ["Sql.Database"]
    doc = audit(FIXTURES / "legacy_pbir")
    assert rules(doc, "PRS004", "inconclusive")
    assert rules(doc, "MOD007")  # int64 vs string


def test_pbix_only_is_flagged_unsupported():
    doc = audit(FIXTURES / "pbix_only")
    assert rules(doc, "PRS003")
    assert doc["inventory"]["counts"]["reports"] == 0


def test_filter_investigation_inactive_relationship():
    model = discover(FIXTURES / "inactive_relationship").models[0]
    res = investigate_filter(SemanticIndex(model), "Customer", "Sales")
    assert res["hypotheses"][0]["confidence"] == "high"
    assert "Inactive relationship" in res["hypotheses"][0]["hypothesis"]


def test_filter_investigation_direction_block():
    model = discover(FIXTURES / "simple_valid").models[0]
    res = investigate_filter(SemanticIndex(model), "Sales", "Customer")
    assert "direction blocks" in res["hypotheses"][0]["hypothesis"]


def test_filter_investigation_measure_modifier():
    model = discover(FIXTURES / "dax_patterns").models[0]
    res = investigate_filter(SemanticIndex(model), "Customer", measure="Ignore Customer")
    assert res["hypotheses"][0]["hypothesis"].startswith("Measure logic removes filters")


def test_filter_investigation_structure_ok_gives_low_confidence_data_hypothesis():
    model = discover(FIXTURES / "simple_valid").models[0]
    res = investigate_filter(SemanticIndex(model), "Customer", "Sales")
    assert res["hypotheses"][-1]["confidence"] == "low"
    assert any("ACTIVE PATH" in e for e in res["evidence"])


def test_synthetic_project_key_findings(synthetic_doc):
    ids = {f["rule_id"] for f in synthetic_doc["findings"]}
    assert {"DAX001", "DAX003", "DAX004", "DAX005", "DAX007", "MOD002", "MOD003", "MOD006", "MOD007",
            "MOD008", "VIS002", "VIS003", "VIS006"} <= ids
    for f in synthetic_doc["findings"]:
        for key in ("id", "title", "category", "severity", "status", "evidence", "path", "object_ref",
                    "explanation", "impact", "recommendation", "verification"):
            assert f[key] not in (None, "", []), (f["id"], key)


def test_finding_ids_are_stable():
    a = audit(FIXTURES / "dax_patterns")
    b = audit(FIXTURES / "dax_patterns")
    assert [f["id"] for f in a["findings"]] == [f["id"] for f in b["findings"]]


def test_every_emitted_rule_is_documented_in_catalog():
    from pbip_forensics.findings.catalog import RULES
    emitted = set()
    for fx in ("dax_patterns", "visual_issues", "legacy_pbir", "ambiguous_path", "pbix_only", "security_cases"):
        emitted |= {f["rule_id"] for f in audit(FIXTURES / fx)["findings"]}
    from tests.conftest import EXAMPLES
    emitted |= {f["rule_id"] for f in audit(EXAMPLES / "synthetic_project")["findings"]}
    assert emitted <= set(RULES), emitted - set(RULES)
