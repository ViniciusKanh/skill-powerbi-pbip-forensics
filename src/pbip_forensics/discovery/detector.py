"""Descoberta e classificação de estruturas de projetos Power BI.

Reconhece: arquivos .pbip, pastas *.Report (definition.pbir), pastas
*.SemanticModel (definition.pbism), PBIR moderno (definition/), PBIR-Legacy
(report.json), TMDL (definition/*.tmdl) e TMSL (model.bim). Arquivos .pbix são
apenas sinalizados (binário fora do escopo desta versão).
"""

from __future__ import annotations

import json
from pathlib import Path

from pbip_forensics.models import ForensicsError, ParseIssue, Project
from pbip_forensics.parsers.model_loader import load_semantic_model
from pbip_forensics.parsers.pbir import load_report
from pbip_forensics.security.safety import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    read_json,
    rel,
    resolve_root,
    safe_walk,
)


def discover(path: str | Path, max_bytes: int = DEFAULT_MAX_FILE_BYTES,
             max_files: int = DEFAULT_MAX_FILES) -> Project:
    """Localiza relatórios e modelos sob `path` e os carrega (somente leitura)."""
    root = resolve_root(path)
    files, skipped = safe_walk(root, max_files)
    project = Project(root=root.name, skipped=skipped)
    report_dirs: set[Path] = set()
    model_dirs: set[Path] = set()
    for f in files:
        low = f.name.lower()
        if low.endswith(".pbip"):
            project.pbip_files.append(rel(root, f))
            try:
                meta = read_json(root, f, max_bytes)
                for art in (meta.get("artifacts", []) if isinstance(meta, dict) else []) or []:
                    rpath = ((art or {}).get("report") or {}).get("path")
                    if rpath and not (f.parent / rpath).resolve().is_dir():
                        project.issues.append(ParseIssue(rel(root, f), f"Referenced report folder not "
                                                         f"found: {rpath}", kind="structure"))
            except (json.JSONDecodeError, UnicodeDecodeError, ForensicsError) as exc:
                project.issues.append(ParseIssue(rel(root, f), f"Invalid .pbip file: {exc}"))
        elif low == "definition.pbir":
            report_dirs.add(f.parent)
        elif low == "definition.pbism" or (low == "model.bim" and f.parent.name.endswith(".SemanticModel")):
            model_dirs.add(f.parent)
        elif low.endswith(".pbix") or low.endswith(".pbit"):
            project.issues.append(ParseIssue(rel(root, f), "Binary PBIX/PBIT is not supported; save as "
                                             "PBIP (File > Save as > Power BI project)", kind="unsupported"))
    # Pastas *.Report / *.SemanticModel sem arquivo de definição também são sinalizadas.
    for f in files:
        for parent in f.parents:
            if parent == root.parent:
                break
            if parent.name.endswith(".Report") and parent not in report_dirs:
                report_dirs.add(parent)
            if parent.name.endswith(".SemanticModel") and parent not in model_dirs:
                model_dirs.add(parent)
    for mdir in sorted(model_dirs):
        project.models.append(load_semantic_model(root, mdir, max_bytes))
    for rdir in sorted(report_dirs):
        project.reports.append(load_report(root, rdir, max_bytes))
    return project
