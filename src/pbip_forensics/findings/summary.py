"""Consolidação de achados: deduplicação por ID estável, ordenação e distribuições."""

from __future__ import annotations

from collections import Counter
from typing import Any

from pbip_forensics.models import SEVERITIES, STATUSES, Finding, sort_findings, to_jsonable


def finalize(findings: list[Finding]) -> dict[str, Any]:
    """Deduplica por ID estável, ordena e calcula distribuições."""
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.id, f)
    ordered = sort_findings(list(unique.values()))
    sev = Counter(f.severity for f in ordered)
    st = Counter(f.status for f in ordered)
    return {"findings": to_jsonable(ordered),
            "severity_breakdown": {s: sev.get(s, 0) for s in SEVERITIES},
            "status_breakdown": {s: st.get(s, 0) for s in STATUSES}}
