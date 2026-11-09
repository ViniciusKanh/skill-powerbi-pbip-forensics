"""Script da skill: leitura de export JSON do Performance Analyzer."""

from __future__ import annotations

import json
from pathlib import Path

from pbip_forensics.analyzers.performance import parse_performance, performance_findings
from pbip_forensics.entrypoints.common import skill_emit, skill_header, skill_parser, skill_run
from pbip_forensics.findings.summary import finalize
from pbip_forensics.models import ForensicsError
from pbip_forensics.security.safety import read_json


def perf_log_main(argv: list[str] | None = None) -> int:
    p = skill_parser("Rank visuals by measured duration from a Performance Analyzer export.")
    p.add_argument("--input", required=True, help="Performance Analyzer export (.json)")
    p.add_argument("--high-ms", type=float, default=3000.0)
    p.add_argument("--medium-ms", type=float, default=1000.0)
    a = p.parse_args(argv)
    path = Path(a.input).expanduser()
    if not path.is_file():
        raise ForensicsError(f"Performance log not found: {path}", 2)
    path = path.resolve()
    try:
        data = read_json(path.parent, path, int(a.max_file_mb * 1024 * 1024))
    except json.JSONDecodeError as exc:
        raise ForensicsError(f"Performance log is not valid JSON: {exc}", 5) from exc
    perf = parse_performance(data)
    findings = performance_findings(perf, path.name, {"high_ms": a.high_ms, "medium_ms": a.medium_ms})
    doc = {**skill_header("perf_log", None), **finalize(findings), "performance": perf,
           "performance_source": path.name,
           "limitations": ["Durations come only from the provided log; 'Other' is derived and includes queueing."]}
    skill_emit(doc, a.output, "perf_log.json", [])
    return 0


def main(argv: list[str] | None = None) -> int:
    return skill_run(perf_log_main, argv)
