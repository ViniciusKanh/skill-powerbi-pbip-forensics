"""Testes da combinação de saídas dos scripts (reporting/merge.py)."""

import json

from pbip_forensics.reporting.merge import merge_documents
from pbip_forensics.reporting.render import render
from tests.conftest import EXAMPLES

OUT = EXAMPLES / "sample_reports" / "skill_outputs"


def test_merge_dedupes_and_prefers_project_name():
    docs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(OUT.glob("*.json"))]
    merged = merge_documents(docs + docs)  # duplicado de propósito
    ids = [f["id"] for f in merged["findings"]]
    assert len(ids) == len(set(ids))
    assert merged["project"] == "synthetic_project"
    assert merged["performance"] and merged["change_impact"] and merged["investigations"]
    assert sum(merged["severity_breakdown"].values()) == len(ids)
    assert "## Evidence Appendix" in render(merged, "markdown")


def test_merge_without_performance_adds_limitation():
    merged = merge_documents([{"script": "model_audit", "project": "p", "findings": []}, "not-a-dict"])
    assert any("No Performance Analyzer log" in x for x in merged["limitations"])
    assert merged["findings"] == []
