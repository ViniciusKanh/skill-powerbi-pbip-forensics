"""Script da skill: auditoria completa em um único comando (HTML + Markdown + JSON)."""

from __future__ import annotations

import sys

from pbip_forensics.automation import DEFAULT_EXCLUDES, console_summary, run_full
from pbip_forensics.entrypoints.common import skill_parser, skill_run


def full_audit_main(argv: list[str] | None = None) -> int:
    p = skill_parser("One-shot audit: inventory, model, DAX, visuals, performance (auto-detected) and report.")
    p.add_argument("--project", required=True, help="PBIP project folder authorized for reading")
    p.add_argument("--performance", help="Performance Analyzer export; auto-detected inside the project if omitted")
    p.add_argument("--lang", choices=["en", "pt-BR"], default="en")
    p.add_argument("--exclude", action="append", default=None,
                   help=f"folder name to skip (repeatable); default: {', '.join(sorted(DEFAULT_EXCLUDES))}")
    p.add_argument("--no-default-excludes", action="store_true", help="scan every folder")
    a = p.parse_args(argv)
    excludes = set() if a.no_default_excludes else set(DEFAULT_EXCLUDES)
    excludes |= {x.lower() for x in a.exclude or []}
    doc, files = run_full(a.project, a.performance, a.output, a.lang, excludes, int(a.max_file_mb * 1024 * 1024))
    print(console_summary(doc, files), file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    return skill_run(full_audit_main, argv)
