"""Conversão de problemas de parsing/estrutura em achados (PRS/SEC)."""

from __future__ import annotations

from pbip_forensics.models import Finding, ParseIssue, Project

_ISSUE_RULES = {
    "parse-error": ("PRS001", "MEDIUM", "confirmed", "File could not be fully parsed"),
    "read-error": ("PRS001", "MEDIUM", "confirmed", "File could not be read"),
    "structure": ("PRS002", "LOW", "confirmed", "Project structure issue"),
    "unsupported": ("PRS003", "INFO", "confirmed", "Unsupported artifact"),
    "limited-support": ("PRS004", "INFO", "inconclusive", "Limited support for this format"),
    "security": ("SEC001", "INFO", "confirmed", "Item skipped by security policy"),
}


def issue_findings(issues: list[ParseIssue]) -> list[Finding]:
    out = []
    for iss in issues:
        rule = _ISSUE_RULES.get(iss.kind)
        if rule is None:
            continue
        rid, sev, status, title = rule
        out.append(Finding(
            rid, f"{title}: {iss.path}", "Parsing", sev, status, [iss.message], iss.path,
            f"issue/{iss.path}/{iss.line}/{iss.message[:40]}",
            "The engine could not interpret this file or structure as documented.",
            "Objects in this file are missing from the analysis; related findings may be incomplete.",
            "Open and re-save the project in a current Power BI Desktop, or fix the file manually.",
            "Validate the file against its published JSON schema or open it in Power BI Desktop.", line=iss.line))
    return out


def collect_issues(project: Project) -> list[ParseIssue]:
    """Reúne problemas de parsing do projeto, modelos e relatórios."""
    issues = list(project.issues)
    for m in project.models:
        issues.extend(m.issues)
    for r in project.reports:
        issues.extend(r.issues)
    return issues
