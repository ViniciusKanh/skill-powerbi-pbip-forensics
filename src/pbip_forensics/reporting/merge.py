"""Combina saídas JSON dos scripts independentes em um único documento de auditoria."""

from __future__ import annotations

from collections import Counter
from typing import Any

from pbip_forensics.models import SEVERITIES, SEVERITY_RANK, STATUSES, TOOL_NAME, TOOL_VERSION


def merge_documents(docs: list[dict[str, Any]]) -> dict[str, Any]:
    """Une achados (deduplicados por ID), inventário, desempenho, diff e investigações."""
    merged: dict[str, Any] = {
        "tool": TOOL_NAME, "version": TOOL_VERSION, "generated_at": "", "project": None,
        "scope": {"project": None, "read_only": True, "performance_log": None, "modules": []},
        "inventory": {}, "findings": [], "dependency_map": [], "performance": None, "change_impact": None,
        "investigations": [], "parse_issues": [], "limitations": [],
    }
    seen: dict[str, dict[str, Any]] = {}
    from_diff = False
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        # O nome do projeto auditado tem prioridade sobre o rótulo "antes -> depois" do diff.
        if doc.get("project") and (merged["project"] is None or (from_diff and doc.get("script") != "diff")):
            merged["project"] = doc["project"]
            from_diff = doc.get("script") == "diff"
        merged["generated_at"] = max(merged["generated_at"], str(doc.get("generated_at") or ""))
        script = doc.get("script") or doc.get("type") or "audit"
        if script not in merged["scope"]["modules"]:
            merged["scope"]["modules"].append(script)
        if doc.get("inventory") and not merged["inventory"]:
            merged["inventory"] = doc["inventory"]
        for f in doc.get("findings", []) or []:
            if isinstance(f, dict) and f.get("id"):
                seen.setdefault(f["id"], f)
        merged["dependency_map"].extend(doc.get("dependency_map", []) or [])
        if doc.get("performance"):
            merged["performance"] = doc["performance"]
            merged["scope"]["performance_log"] = doc.get("performance_source")
        if doc.get("change_impact"):
            merged["change_impact"] = doc["change_impact"]
        merged["investigations"].extend(doc.get("investigations", []) or [])
        for issue in doc.get("parse_issues", []) or []:
            if issue not in merged["parse_issues"]:
                merged["parse_issues"].append(issue)
        for lim in doc.get("limitations", []) or []:
            if lim not in merged["limitations"]:
                merged["limitations"].append(lim)
    status_rank = {s: i for i, s in enumerate(STATUSES)}
    merged["findings"] = sorted(seen.values(), key=lambda f: (SEVERITY_RANK.get(f.get("severity"), 9),
                                                              status_rank.get(f.get("status"), 9), f["id"]))
    sev = Counter(f["severity"] for f in merged["findings"])
    st = Counter(f["status"] for f in merged["findings"])
    merged["severity_breakdown"] = {s: sev.get(s, 0) for s in SEVERITIES}
    merged["status_breakdown"] = {s: st.get(s, 0) for s in STATUSES}
    merged["scope"]["project"] = merged["project"]
    if merged["performance"] is None:
        merged["limitations"].append("No Performance Analyzer log provided: no runtime measurements are available.")
    return merged
