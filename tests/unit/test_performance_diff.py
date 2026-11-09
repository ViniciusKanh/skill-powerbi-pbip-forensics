"""Testes do leitor do Performance Analyzer e da comparação de versões."""

import json

import pytest

from pbip_forensics.analyzers.diff import diff_projects
from pbip_forensics.analyzers.performance import parse_performance, performance_findings
from pbip_forensics.discovery.detector import discover
from pbip_forensics.models import ForensicsError
from tests.conftest import EXAMPLES, FIXTURES, audit, rules


def load(name: str):
    return json.loads((FIXTURES / "performance" / name).read_text(encoding="utf-8"))


def test_multi_visual_log_breakdown():
    perf = parse_performance(load("multi_visual.json"))
    assert len(perf["visuals"]) == 5
    top = perf["visuals"][0]
    assert top["visual_title"] == "Customer Accounts"
    assert top["total_ms"] == pytest.approx(3420.0, abs=0.01)
    assert top["dax_query_ms"] == pytest.approx(3198.0, abs=0.01)
    assert top["other_ms"] == pytest.approx(42.0, abs=0.01)
    assert top["queries"] and top["row_counts"] == [5000]
    totals = [v["total_ms"] for v in perf["visuals"]]
    assert totals == sorted(totals, reverse=True)


def test_performance_findings_only_from_measurements():
    perf = parse_performance(load("multi_visual.json"))
    f = performance_findings(perf, "p.json")
    assert [x.severity for x in f] == ["HIGH", "MEDIUM", "MEDIUM"]
    assert all(x.status == "confirmed" for x in f)
    high = performance_findings(perf, "p.json", {"high_ms": 99999, "medium_ms": 99999})
    assert high == []


def test_malformed_and_wrong_shape_logs():
    with pytest.raises(ForensicsError):
        parse_performance({"foo": []})
    with pytest.raises(json.JSONDecodeError):
        load("malformed.json")
    perf = parse_performance(load("partial.json"))
    assert perf["visuals"][0]["total_ms"] is None
    assert any("malformed event" in w for w in perf["warnings"])
    assert any("no end timestamp" in w for w in perf["warnings"])


def test_audit_without_log_states_limitation():
    doc = audit(FIXTURES / "simple_valid")
    assert doc["performance"] is None
    assert any("No Performance Analyzer log" in x for x in doc["limitations"])


def test_audit_with_log_maps_project_visuals():
    doc = audit(EXAMPLES / "synthetic_project", parse_performance(load("multi_visual.json")))
    perf = rules(doc, "PERF001")
    assert any("Mapped to project visual" in " ".join(f["evidence"]) for f in perf)


def test_diff_measure_modified_with_impact():
    d = diff_projects(discover(FIXTURES / "diff_before"), discover(FIXTURES / "diff_after_measure"))
    mod = [c for c in d["changes"] if c["object_type"] == "measure"]
    assert mod == [{"object_type": "measure", "object": "Total Revenue", "change": "modified",
                    "details": ["DAX expression changed (token-level)"]}]
    imp = d["impacts"][0]
    assert "may require regression testing" in imp["message"]
    assert len(imp["affected_visuals"]) == 2


def test_diff_relationship_change_impact():
    d = diff_projects(discover(FIXTURES / "diff_before"), discover(FIXTURES / "diff_after_relationship"))
    rel = [c for c in d["changes"] if c["object_type"] == "relationship"]
    assert rel and "crossFilteringBehavior: oneDirection -> bothDirections" in rel[0]["details"]
    assert d["impacts"] and d["impacts"][0]["affected_visuals"]


def test_diff_formatting_only_is_not_a_logic_change():
    d = diff_projects(discover(FIXTURES / "diff_before"), discover(FIXTURES / "diff_after_format"))
    assert [c["change"] for c in d["changes"]] == ["modified-formatting"]
    assert d["impacts"] == []


def test_diff_identical_projects():
    d = diff_projects(discover(FIXTURES / "diff_before"), discover(FIXTURES / "diff_before"))
    assert d["changes"] == [] and d["impacts"] == []


def test_diff_removed_measure_still_used_is_flagged():
    d = diff_projects(discover(EXAMPLES / "synthetic_project"), discover(EXAMPLES / "synthetic_project_v2"))
    bonus = [i for i in d["impacts"] if i["change"].startswith("measure Bonus")]
    assert bonus and "broken (confirmed)" in bonus[0]["message"]
