"""Execução automática de ponta a ponta (comando `run` e script `pbip_full_audit.py`).

Um único passo: descobre o projeto, ignora pastas de backup comuns, localiza um
export do Performance Analyzer (se existir), executa todas as análises e grava
HTML + Markdown + JSON numa pasta de saída fora do projeto.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pbip_forensics.analyzers.audit import run_audit
from pbip_forensics.analyzers.performance import parse_performance
from pbip_forensics.discovery.detector import discover
from pbip_forensics.models import ForensicsError
from pbip_forensics.reporting.render import render
from pbip_forensics.security.safety import is_within, prepare_output_dir, read_json, resolve_root

# Pastas tipicamente usadas para cópias antigas do projeto (evitam modelos duplicados).
DEFAULT_EXCLUDES = {"backup", "backups", "bkp", "_backup", "old", "archive", "_archive", ".agents"}
_PERF_HINTS = ("performance", "powerbiperformancedata", "perfanalyzer")


def default_output(root: Path) -> Path:
    """Pasta irmã do projeto: <pasta-do-projeto>-forensics (sempre fora do projeto)."""
    return root.parent / f"{root.name}-forensics"


def find_performance_log(root: Path, max_bytes: int, max_depth: int = 2) -> Path | None:
    """Procura um export válido do Performance Analyzer dentro do projeto (mais recente)."""
    candidates = []
    for p in root.rglob("*.json"):
        if len(p.relative_to(root).parts) > max_depth + 1 or p.is_symlink() or not is_within(root, p):
            continue
        if any(h in p.name.lower() for h in _PERF_HINTS):
            candidates.append(p)
    for p in sorted(candidates, key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            data = read_json(root, p, max_bytes)
            if isinstance(data, dict) and isinstance(data.get("events"), list):
                return p
        except (json.JSONDecodeError, UnicodeDecodeError, ForensicsError):
            continue
    return None


def run_full(project: str | Path, performance: str | Path | None = None, output: str | Path | None = None,
             lang: str = "en", excludes: set[str] | None = None, max_bytes: int = 25 * 1024 * 1024,
             auto_perf: bool = True) -> tuple[dict[str, Any], dict[str, Path]]:
    """Executa a auditoria completa e grava os relatórios. Retorna (documento, arquivos)."""
    root = resolve_root(project)
    proj = discover(root, max_bytes=max_bytes, exclude_dirs=DEFAULT_EXCLUDES if excludes is None else excludes)
    perf_path: Path | None = None
    if performance:
        perf_path = Path(performance).expanduser().resolve()
        if not perf_path.is_file():
            raise ForensicsError(f"Performance log not found: {perf_path}", 2)
    elif auto_perf:
        perf_path = find_performance_log(root, max_bytes)
    perf = None
    if perf_path is not None:
        try:
            perf = parse_performance(read_json(perf_path.parent, perf_path, max_bytes))
        except json.JSONDecodeError as exc:
            raise ForensicsError(f"Performance log is not valid JSON: {exc}", 5) from exc
    doc = run_audit(proj, perf, perf_path.name if perf_path else "")
    excluded = [s for s in proj.skipped if s.startswith("excluded-by-option")]
    if excluded:
        doc["limitations"].append(f"Folders excluded from the scan: {', '.join(x.split(': ', 1)[1] for x in excluded)}")
    if len(proj.models) > 1:
        doc["limitations"].append(f"{len(proj.models)} semantic models found; check for copies of the same model "
                                  "(use --exclude for backup folders).")
    out = prepare_output_dir(output or default_output(root), [root])
    files = {"html": out / "audit-report.html", "markdown": out / "audit-report.md", "json": out / "findings.json"}
    for fmt, path in files.items():
        path.write_text(render(doc, fmt, lang), encoding="utf-8", newline="\n")
    return doc, files


def console_summary(doc: dict[str, Any], files: dict[str, Path], top: int = 5) -> str:
    """Resumo curto para o terminal (sem dados sensíveis)."""
    sev = doc["severity_breakdown"]
    lines = [f"Project: {doc['project']}  |  findings: {sum(sev.values())} "
             + " ".join(f"{k}={v}" for k, v in sev.items() if v),
             f"Performance log: {doc['scope'].get('performance_log') or 'not found (static risks only)'}"]
    hi = [f for f in doc["findings"] if f["severity"] in ("CRITICAL", "HIGH")][:top]
    for f in hi:
        lines.append(f"  [{f['severity']}/{f['status']}] {f['title']}")
    lines.append(f"Report: {files['html']}")
    return "\n".join(lines)
