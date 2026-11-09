"""Diagnóstico de filtros e relacionamentos (Módulo 5).

Combina caminhos de propagação, estado/direção dos relacionamentos,
modificadores de contexto das medidas e filtros de visual/página para
responder perguntas como "por que o cliente selecionado não filtra a tabela X?".

As hipóteses são ordenadas e recebem confiança qualitativa justificada
(high/medium/low). Nenhum valor numérico do relatório é afirmado.
"""

from __future__ import annotations

from typing import Any

from pbip_forensics.analyzers.semantic import SemanticIndex
from pbip_forensics.graph.model_graph import Hop
from pbip_forensics.models import ForensicsError, Visual


def _path_text(path: list[Hop]) -> str:
    return " => ".join(h.describe() for h in path)


def activated_relationships(idx: SemanticIndex, measure: str | None) -> set[str]:
    """IDs de relacionamentos ativados via USERELATIONSHIP/CROSSFILTER na medida."""
    if not measure:
        return set()
    ids = set()
    for _, mod in idx.modifiers_for(measure):
        if mod.relationship is not None and mod.function == "USERELATIONSHIP":
            ids.add(mod.relationship.id)
    return ids


def reaches(idx: SemanticIndex, src: str, dst: str, measure: str | None = None) -> bool:
    if src.lower() == dst.lower():
        return True
    return bool(idx.graph.filter_paths(src, dst, activated_relationships(idx, measure), limit=1))


def investigate_filter(idx: SemanticIndex, from_table: str, to_table: str | None = None,
                       measure: str | None = None, visual: Visual | None = None) -> dict[str, Any]:
    """Investiga por que (ou se) um filtro em `from_table` alcança o alvo."""
    g = idx.graph
    src = g.canon(from_table)
    if src is None:
        raise ForensicsError(f"Table not found in model: {from_table}", 2)
    mcanon = None
    if measure:
        m = idx.measures.get(measure.lower())
        if m is None:
            raise ForensicsError(f"Measure not found in model: {measure}", 2)
        mcanon = m.name
    targets: list[str] = []
    if to_table:
        t = g.canon(to_table)
        if t is None:
            raise ForensicsError(f"Table not found in model: {to_table}", 2)
        targets.append(t)
    if mcanon:
        targets.extend(sorted(idx.base_tables(mcanon) - set(targets)))
    if not targets:
        raise ForensicsError("Provide --to-table and/or --measure", 2)

    evidence: list[str] = []
    hypotheses: list[dict[str, Any]] = []
    activated = activated_relationships(idx, mcanon)
    if mcanon:
        bases = ", ".join(sorted(idx.base_tables(mcanon))) or "(none detected)"
        evidence.append(f"Measure {mcanon} aggregates tables: {bases}")
        evidence.append(f"Measure dependencies: {', '.join(idx.measure_closure(mcanon)) or '(none)'}")

    for tgt in targets:
        if tgt == src:
            evidence.append(f"'{src}' is the target table itself: filters apply directly.")
            continue
        ok = g.filter_paths(src, tgt, activated)
        every = g.all_paths(src, tgt)
        evidence.append(f"Direction-compatible active paths '{src}' -> '{tgt}': {len(ok)}")
        for p in ok[:3]:
            evidence.append("  ACTIVE PATH: " + _path_text(p))
        blocked = [p for p in every if not all(h.allowed or h.rel.id in activated for h in p)]
        for p in blocked[:3]:
            evidence.append("  BLOCKED PATH: " + _path_text(p))
        if len(ok) >= 2:
            hypotheses.append(_hyp(
                f"Ambiguous propagation: '{src}' reaches '{tgt}' through {len(ok)} paths.", "medium",
                "Multiple active direction-compatible paths were found in the relationship graph.",
                ["Check Model view for ambiguity warnings.", "Deactivate or make single-direction one path."]))
        if not ok:
            inactive = [p for p in blocked if any(not h.rel.is_active for h in p)]
            direction = [p for p in blocked if all(h.rel.is_active for h in p)]
            if inactive:
                rel = next(h.rel for h in inactive[0] if not h.rel.is_active)
                hypotheses.append(_hyp(
                    f"Inactive relationship on the only path from '{src}' to '{tgt}': {rel.label()}.", "high",
                    "Structural evidence: the relationship has isActive=false and no other active path exists"
                    + (" and the measure does not activate it with USERELATIONSHIP." if mcanon else "."),
                    ["Confirm isActive=false in Model view.",
                     f"Create a test measure: CALCULATE([<measure>], USERELATIONSHIP('{rel.from_table}'"
                     f"[{rel.from_column}], '{rel.to_table}'[{rel.to_column}])) and compare.",
                     "Decide whether to activate the relationship or use the USERELATIONSHIP measure in visuals."]))
            if direction:
                hop = next(h for h in direction[0] if not h.allowed)
                hypotheses.append(_hyp(
                    f"Cross-filter direction blocks propagation at '{hop.src}' -> '{hop.dst}'.", "high",
                    f"The path exists, but {hop.rel.label()} is single-direction; filters flow only from the "
                    "one side to the many side.",
                    ["Verify the cross-filter direction in Model view.",
                     f"Test with CROSSFILTER('{hop.rel.from_table}'[{hop.rel.from_column}], "
                     f"'{hop.rel.to_table}'[{hop.rel.to_column}], BOTH) inside a test measure.",
                     "Prefer filtering through a shared dimension instead of enabling bidirectional filters."]))
            if not every:
                hypotheses.append(_hyp(
                    f"No relationship path connects '{src}' and '{tgt}'.", "high",
                    "The relationship graph has no path between these tables, active or inactive.",
                    ["Create a relationship via a shared key or dimension.",
                     "If the table is a parameter table, read it explicitly in DAX (SELECTEDVALUE/TREATAS)."]))
    if mcanon:
        for owner, mod in idx.modifiers_for(mcanon):
            if mod.function in ("ALL", "REMOVEFILTERS", "ALLEXCEPT", "ALLSELECTED"):
                hit = [t for t in mod.targets if src.lower() in t.lower() or
                       any(x.lower() in t.lower() for x in targets)]
                evidence.append(f"Modifier in {owner}: {mod.function}({', '.join(mod.targets)}) [{mod.context}]")
                if hit and mod.function != "ALLEXCEPT":
                    hypotheses.insert(0, _hyp(
                        f"Measure logic removes filters: {owner} uses {mod.function}({', '.join(mod.targets)}).",
                        "high", "Static DAX evidence: the filter modifier targets the selected table or the "
                        "aggregated table, so selections there are ignored by design.",
                        ["Compare the measure with its base measure under the same selection.",
                         "If selections must apply, remove the modifier or use KEEPFILTERS/narrower targets."]))
            elif mod.function == "CROSSFILTER":
                evidence.append(f"Modifier in {owner}: CROSSFILTER({', '.join(mod.targets)}, {mod.direction})")
                if mod.direction == "NONE":
                    hypotheses.insert(0, _hyp(
                        f"{owner} disables a relationship with CROSSFILTER(..., NONE).", "high",
                        "Static DAX evidence of propagation being switched off.",
                        ["Review the CROSSFILTER call and the relationship it targets."]))
    if visual is not None:
        vf = [f for f in visual.fields if f.usage == "filter"]
        evidence.append(f"Visual '{visual.title or visual.name}' ({visual.visual_type}) has {len(vf)} visual-level "
                        "filter(s): " + ", ".join(f"{f.entity}[{f.property}]" for f in vf))
        if vf:
            hypotheses.append(_hyp(
                "Visual-level filters may restrict or widen rows independently of slicers.", "medium",
                "Filters are stored in the visual's filterConfig.",
                ["Open the Filters pane for this visual and review each filter."]))
    if not any(h["confidence"] == "high" for h in hypotheses):
        hypotheses.append(_hyp(
            "Model structure allows propagation; the cause is likely data-level or interaction-level.", "low",
            "No structural blocker was found in the files. Data cannot be inspected statically.",
            ["Check for unmatched keys: rows of the many-side table whose key has no match (shown as (Blank)).",
             "Check key data types, trailing spaces and case differences in Power Query.",
             "Check Format > Edit interactions between the slicer and the visual.",
             "Check bookmarks or sync-slicer settings that may override selections."]))
    for rank, h in enumerate(hypotheses, start=1):
        h["rank"] = rank
    return {"type": "filter-investigation", "from_table": src, "targets": targets, "measure": mcanon,
            "visual": visual.name if visual else None, "evidence": evidence, "hypotheses": hypotheses,
            "note": "Deterministic evidence comes from model files; hypotheses require verification in Power BI."}


def _hyp(text: str, confidence: str, justification: str, steps: list[str]) -> dict[str, Any]:
    return {"hypothesis": text, "confidence": confidence, "justification": justification,
            "verification_steps": steps}
