"""Regras agregadas novas (MOD010, DAX014, COL001) e camada de insights do relatório."""

import math
from pathlib import Path

from pbip_forensics.reporting.html_report import to_html_report
from pbip_forensics.reporting.insights import compute_insights, scores
from tests.conftest import FIXTURES, audit, rules

ROOT = Path(__file__).resolve().parents[2]


def test_aggregated_rules_are_single_info_findings():
    doc = audit(FIXTURES / "simple_valid")
    for rid in ("MOD010", "DAX014"):
        f = rules(doc, rid)
        assert len(f) == 1 and f[0]["severity"] == "INFO" and f[0]["status"] == "potential", rid


def test_unused_columns_reported_per_table():
    doc = audit(FIXTURES / "disconnected_dimension")
    cols = rules(doc, "COL001")
    assert cols and all(f["severity"] == "INFO" for f in cols)
    assert not rules(audit(FIXTURES / "simple_valid"), "COL001")


def test_score_formula_and_grades():
    fs = [{"category": "Relationships", "severity": "HIGH", "status": "confirmed"}]
    s = scores(fs, has_perf=False)
    model = next(a for a in s["areas"] if a["key"] == "model")
    assert model["score"] == round(100 * math.exp(-8 / 40))
    perf = next(a for a in s["areas"] if a["key"] == "performance")
    assert perf["score"] is None and perf["grade"] == "not_measured"
    assert scores([], has_perf=False)["overall"] == 100


def test_insights_on_synthetic_project():
    doc = audit(ROOT / "examples" / "synthetic_project")
    for lang in ("en", "pt-BR"):
        ins = compute_insights(doc, lang)
        assert 0 <= ins["scores"]["overall"] <= 100
        assert ins["narrative"] and ins["quick_wins"]
        assert len({w["rule_id"] for w in ins["quick_wins"]}) == len(ins["quick_wins"])
        g = ins["model_graph"]
        assert g["nodes"] and g["edges"]
        assert any(e.get("ambiguous") for e in g["edges"])  # MOD006 HIGH do projeto sintético
        assert ins["measures"]["total"] > 0 and ins["measures"]["complex"] and ins["pages"]


def test_html_contains_overview_and_model_map():
    doc = audit(ROOT / "examples" / "synthetic_project")
    html = to_html_report(doc, lang="pt-BR")
    assert 'id="overview"' in html and "<svg" in html and "Mapa do modelo" in html
    assert "<script src=" not in html  # autocontido, sem recursos externos
