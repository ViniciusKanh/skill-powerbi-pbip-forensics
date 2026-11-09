"""Script da skill: auditoria de relacionamentos, estrutura do modelo e DAX."""

from __future__ import annotations

from pbip_forensics.analyzers.semantic import build_indexes
from pbip_forensics.analyzers.stage_model import BASE_LIMITATIONS, model_stage
from pbip_forensics.discovery.detector import discover
from pbip_forensics.entrypoints.common import skill_emit, skill_header, skill_parser, skill_run
from pbip_forensics.findings.summary import finalize
from pbip_forensics.security.safety import resolve_root


def model_audit_main(argv: list[str] | None = None) -> int:
    p = skill_parser("Audit semantic model relationships, structure and DAX (static, read-only).")
    p.add_argument("--project", required=True, help="PBIP project folder authorized for reading")
    a = p.parse_args(argv)
    root = resolve_root(a.project)
    project = discover(root, max_bytes=int(a.max_file_mb * 1024 * 1024))
    findings, limitations = model_stage(project, build_indexes(project))
    doc = {**skill_header("model_audit", project.root), **finalize(findings),
           "limitations": [*BASE_LIMITATIONS, *limitations]}
    skill_emit(doc, a.output, "model_audit.json", [root])
    return 0


def main(argv: list[str] | None = None) -> int:
    return skill_run(model_audit_main, argv)
