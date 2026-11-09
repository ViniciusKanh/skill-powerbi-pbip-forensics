"""Estágio de auditoria do modelo: parsing, relacionamentos/estrutura e DAX.

A união deste estágio com o estágio de visuais é exatamente o conjunto de
achados estáticos do comando `audit` (paridade com os scripts da skill).
"""

from __future__ import annotations

from pbip_forensics.analyzers.dax_rules import dax_findings
from pbip_forensics.analyzers.model_rules import model_findings
from pbip_forensics.analyzers.semantic import SemanticIndex
from pbip_forensics.findings.issues import collect_issues, issue_findings
from pbip_forensics.models import Finding, Project

BASE_LIMITATIONS = [
    "Static analysis only: DAX is not executed and no data values are read.",
    "Filter-propagation results are derived from relationship metadata, not from query plans.",
]


def model_stage(project: Project, indexes: dict[str, SemanticIndex]) -> tuple[list[Finding], list[str]]:
    """Achados de parsing, relacionamentos/estrutura e DAX."""
    findings = issue_findings(collect_issues(project))
    limitations: list[str] = []
    for m in project.models:
        findings.extend(model_findings(m, indexes[m.path]))
        findings.extend(dax_findings(m, indexes[m.path]))
        if any(r.cross_filter.lower() == "automatic" for r in m.relationships):
            limitations.append(f"Model '{m.name}': crossFilteringBehavior 'automatic' treated as single direction.")
    return findings, limitations
