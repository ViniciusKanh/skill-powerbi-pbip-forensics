"""Leitura e análise de exports JSON do Performance Analyzer (Módulo 6).

Formato: o Microsoft Learn documenta apenas a exportação (.json) e as categorias
(DAX query, Direct query, Visual display, Other, Evaluated parameters); o layout
do JSON é descrito no exemplo oficial "Power BI Performance Analyzer Export File
Format" (repositório powerbi-desktop-samples). Este leitor espera:

    {"version": "...", "events": [
        {"name": "Visual Container Lifecycle", "id": "...", "start": ISO, "end": ISO,
         "metrics": {"visualTitle": ..., "visualId": ..., "visualType": ...}},
        {"name": "Query" | "Execute DAX Query" | "Execute Direct Query" | "Render" |
                 "Data View Transform" | ..., "id": ..., "parentId": ..., "start": ..., "end": ...}]}

Campos ausentes são tolerados e registrados; nenhum tempo é inventado.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pbip_forensics.models import Finding, ForensicsError

LIFECYCLE = "Visual Container Lifecycle"
CATEGORY_BY_EVENT = {
    "Execute DAX Query": "dax_query_ms",
    "Execute Direct Query": "direct_query_ms",
    "Render": "visual_display_ms",
    "Evaluated Parameters": "evaluated_parameters_ms",
}
DEFAULT_THRESHOLDS = {"high_ms": 3000.0, "medium_ms": 1000.0}


def _ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    # Python 3.11 aceita frações com até 6 dígitos; normaliza frações maiores.
    if "." in text:
        head, _, rest = text.partition(".")
        digits = "".join(ch for ch in rest if ch.isdigit())
        tz = rest[len(digits):]
        text = f"{head}.{digits[:6].ljust(6, '0')}{tz}"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _dur(ev: dict[str, Any]) -> float | None:
    s, e = _ts(ev.get("start")), _ts(ev.get("end"))
    if s is None or e is None:
        return None
    return round((e - s).total_seconds() * 1000.0, 3)


def parse_performance(data: Any) -> dict[str, Any]:
    """Valida o export e agrega durações por visual (somente valores medidos)."""
    if not isinstance(data, dict) or not isinstance(data.get("events"), list):
        raise ForensicsError("Invalid Performance Analyzer export: expected an object with an 'events' list", 5)
    events = [e for e in data["events"] if isinstance(e, dict)]
    by_id = {str(e.get("id")): e for e in events if e.get("id") is not None}
    children: dict[str, list[dict[str, Any]]] = {}
    for e in events:
        if e.get("parentId") is not None:
            children.setdefault(str(e["parentId"]), []).append(e)
    warnings: list[str] = []
    skipped = sum(1 for e in data["events"] if not isinstance(e, dict))
    if skipped:
        warnings.append(f"{skipped} malformed event entries ignored")
    visuals: list[dict[str, Any]] = []
    for e in events:
        if e.get("name") != LIFECYCLE:
            continue
        metrics: dict[str, Any] = e["metrics"] if isinstance(e.get("metrics"), dict) else {}
        total = _dur(e)
        row: dict[str, Any] = {
            "visual_id": metrics.get("visualId"), "visual_title": metrics.get("visualTitle"),
            "visual_type": metrics.get("visualType"), "status": metrics.get("status"),
            "total_ms": total, "dax_query_ms": 0.0, "direct_query_ms": 0.0, "visual_display_ms": 0.0,
            "evaluated_parameters_ms": 0.0, "other_ms": None, "queries": [], "row_counts": [],
            "start": e.get("start"),
        }
        stack = list(children.get(str(e.get("id")), []))
        seen: set[int] = set()
        while stack:
            child = stack.pop()
            if id(child) in seen:
                continue
            seen.add(id(child))
            cat = CATEGORY_BY_EVENT.get(str(child.get("name")))
            d = _dur(child)
            if cat and d is not None:
                row[cat] = round(row[cat] + d, 3)
            cm: dict[str, Any] = child["metrics"] if isinstance(child.get("metrics"), dict) else {}
            if child.get("name") == "Execute DAX Query" and cm.get("QueryText"):
                row["queries"].append(str(cm["QueryText"])[:4000])
            if cm.get("RowCount") is not None:
                row["row_counts"].append(cm.get("RowCount"))
            stack.extend(children.get(str(child.get("id")), []))
        if total is not None:
            known = row["dax_query_ms"] + row["direct_query_ms"] + row["visual_display_ms"] + \
                row["evaluated_parameters_ms"]
            row["other_ms"] = round(max(total - known, 0.0), 3)
        else:
            warnings.append(f"Visual '{row['visual_title'] or row['visual_id']}' has no end timestamp")
        visuals.append(row)
    if not visuals:
        warnings.append("No 'Visual Container Lifecycle' events found; no per-visual timings available")
    orphan = sum(1 for e in events if e.get("parentId") is not None and str(e["parentId"]) not in by_id)
    if orphan:
        warnings.append(f"{orphan} events reference a parentId that is not in the file")
    visuals.sort(key=lambda r: (-(r["total_ms"] or 0.0), str(r["visual_title"])))
    return {"version": data.get("version"), "event_count": len(events),
            "user_actions": sum(1 for e in events if e.get("name") == "User Action"),
            "visuals": visuals, "warnings": warnings}


def dominant_component(row: dict[str, Any]) -> str | None:
    parts = {k: row.get(k) or 0.0 for k in ("dax_query_ms", "direct_query_ms", "visual_display_ms", "other_ms")}
    if not any(parts.values()):
        return None
    return max(parts, key=lambda k: parts[k])


_ACTIONS = {
    "dax_query_ms": "DAX query time dominates: copy the query (Copy query) into DAX query view or DAX Studio, "
                    "check server timings and review the measures involved.",
    "direct_query_ms": "DirectQuery time dominates: inspect the source query, indexes and gateway latency.",
    "visual_display_ms": "Visual display dominates: reduce data points/rows, simplify formatting or custom "
                         "visual rendering.",
    "other_ms": "'Other' dominates: the visual waited for other operations (queueing on the UI thread); reduce "
                "the number of visuals on the page or use bookmarks/drill-through.",
}


def performance_findings(perf: dict[str, Any], source: str, thresholds: dict[str, float] | None = None,
                         visual_names: dict[str, str] | None = None) -> list[Finding]:
    """Gera achados apenas a partir de durações medidas no log."""
    th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    out: list[Finding] = []
    for row in perf["visuals"]:
        total = row.get("total_ms")
        if total is None or total < th["medium_ms"]:
            continue
        sev = "HIGH" if total >= th["high_ms"] else "MEDIUM"
        dom = dominant_component(row)
        name = row.get("visual_title") or row.get("visual_id") or "(untitled)"
        page = (visual_names or {}).get(str(row.get("visual_id")), "")
        ev = [f"Measured total: {total:.1f} ms (threshold {th['medium_ms']:.0f}/{th['high_ms']:.0f} ms)",
              f"DAX query: {row['dax_query_ms']:.1f} ms; Direct query: {row['direct_query_ms']:.1f} ms; "
              f"Visual display: {row['visual_display_ms']:.1f} ms; Other (derived): {row['other_ms']:.1f} ms"]
        if page:
            ev.append(f"Mapped to project visual: {page}")
        out.append(Finding(
            "PERF001", f"Slow visual in recorded session: {name}", "Performance", sev, "confirmed", ev, source,
            f"perf/{row.get('visual_id')}/{row.get('start')}",
            "Duration measured by Performance Analyzer during the recorded session.",
            "Users experience delay on this visual; durations include queueing on the UI thread.",
            _ACTIONS.get(dom or "", "Review the visual."),
            "Record a new session with Performance Analyzer (clear cache by refreshing visuals) and compare."))
    return out
