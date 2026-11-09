"""Script da skill: combina os JSON dos scripts e gera relatório Markdown/HTML/JSON."""

from __future__ import annotations

import json
from pathlib import Path

from pbip_forensics.entrypoints.common import skill_parser, skill_run
from pbip_forensics.models import ForensicsError
from pbip_forensics.reporting.merge import merge_documents
from pbip_forensics.reporting.render import render
from pbip_forensics.security.safety import prepare_output_dir, read_json


def report_main(argv: list[str] | None = None) -> int:
    p = skill_parser("Merge JSON outputs of the other scripts into one audit report.")
    p.add_argument("--input", nargs="+", required=True, help="JSON files produced by the other scripts")
    p.add_argument("--format", choices=["markdown", "html", "json", "all"], default="all")
    p.add_argument("--lang", choices=["en", "pt-BR"], default="en")
    a = p.parse_args(argv)
    docs = []
    for item in a.input:
        path = Path(item).expanduser()
        if not path.is_file():
            raise ForensicsError(f"Input not found: {path}", 2)
        path = path.resolve()
        try:
            docs.append(read_json(path.parent, path, int(a.max_file_mb * 1024 * 1024)))
        except json.JSONDecodeError as exc:
            raise ForensicsError(f"Invalid JSON input {path.name}: {exc}", 2) from exc
    doc = merge_documents(docs)
    formats = ["markdown", "html", "json"] if a.format == "all" else [a.format]
    ext = {"markdown": ".md", "html": ".html", "json": ".json"}
    if not a.output:
        print(render(doc, formats[0], a.lang))
        return 0
    out = prepare_output_dir(a.output, [])
    for f in formats:
        name = "audit-findings.json" if f == "json" else f"audit-report{ext[f]}"
        (out / name).write_text(render(doc, f, a.lang), encoding="utf-8", newline="\n")
        print(f"wrote {name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return skill_run(report_main, argv)
