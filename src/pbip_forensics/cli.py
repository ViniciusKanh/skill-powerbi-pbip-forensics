"""Interface de linha de comando do Power BI PBIP Forensics.

Códigos de saída:
 0 sucesso | 1 achados >= --fail-on | 2 entrada inválida | 3 limite excedido
 4 recusa por política de segurança | 5 log de desempenho inválido | 10 erro interno
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import webbrowser
from pathlib import Path
from typing import Any

from pbip_forensics.analyzers.audit import run_audit
from pbip_forensics.analyzers.diff import diff_projects
from pbip_forensics.analyzers.filters import investigate_filter
from pbip_forensics.analyzers.inventory import build_inventory
from pbip_forensics.analyzers.performance import parse_performance, performance_findings
from pbip_forensics.analyzers.semantic import SemanticIndex
from pbip_forensics.automation import DEFAULT_EXCLUDES, console_summary, run_full
from pbip_forensics.discovery.detector import discover
from pbip_forensics.models import SEVERITY_RANK, TOOL_VERSION, ForensicsError, Project, to_jsonable
from pbip_forensics.reporting.render import render
from pbip_forensics.security.safety import prepare_output_dir, read_json, resolve_root

FORMATS = {"markdown": ".md", "html": ".html", "json": ".json"}


def _err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


def _write(out_dir: Path, name: str, content: str) -> Path:
    target = out_dir / name
    target.write_text(content, encoding="utf-8", newline="\n")
    return target


def _emit(doc: Any, args: argparse.Namespace, stem: str, roots: list[Path]) -> None:
    """Grava no diretório de saída (se informado) ou imprime em stdout."""
    fmt = getattr(args, "format", "json")
    formats = list(FORMATS) if fmt == "all" else [fmt]
    if getattr(args, "output", None):
        out = prepare_output_dir(args.output, roots)
        for f in formats:
            text = render(doc, f, args.lang) if "type" not in doc else (
                json.dumps(doc, indent=2, ensure_ascii=False) if f == "json" else _simple_md(doc, f, args.lang))
            path = _write(out, f"{stem}{FORMATS[f]}", text)
            print(f"wrote {path.name}", file=sys.stderr)
    else:
        f = formats[0]
        print(render(doc, f, args.lang) if "type" not in doc else (
            json.dumps(doc, indent=2, ensure_ascii=False) if f == "json" else _simple_md(doc, f, args.lang)))


def _simple_md(doc: dict[str, Any], fmt: str, lang: str = "en") -> str:
    """Envolve documentos auxiliares (scan/diff/investigate) no relatório padrão."""
    wrapper: dict[str, Any] = {
        "tool": "powerbi-pbip-forensics", "version": TOOL_VERSION, "generated_at": "", "project": doc.get("project"),
        "scope": {"project": doc.get("project"), "read_only": True, "modules": [doc.get("type", "scan")]},
        "inventory": doc.get("inventory", {}), "severity_breakdown": {}, "status_breakdown": {},
        "findings": doc.get("findings", []), "dependency_map": doc.get("dependency_map", []),
        "performance": doc.get("performance"), "change_impact": doc if doc.get("type") == "change-impact" else None,
        "investigations": [doc] if doc.get("type") == "filter-investigation" else [],
        "limitations": doc.get("limitations", []),
    }
    return render(wrapper, fmt, lang)


def _load(path: str, max_mb: float) -> tuple[Project, Path]:
    root = resolve_root(path)
    return discover(root, max_bytes=int(max_mb * 1024 * 1024)), root


def _load_perf(path: str, max_mb: float) -> tuple[dict[str, Any], str]:
    p = Path(path).expanduser()
    if not p.is_file():
        raise ForensicsError(f"Performance log not found: {p}", 2)
    p = p.resolve()
    try:
        data = read_json(p.parent, p, int(max_mb * 1024 * 1024))
    except json.JSONDecodeError as exc:
        raise ForensicsError(f"Performance log is not valid JSON: {exc}", 5) from exc
    return parse_performance(data), p.name


def _fail_code(doc: dict[str, Any], fail_on: str | None) -> int:
    if not fail_on:
        return 0
    limit = SEVERITY_RANK[fail_on]
    return 1 if any(SEVERITY_RANK[f["severity"]] <= limit for f in doc.get("findings", [])) else 0


def cmd_scan(args: argparse.Namespace) -> int:
    project, root = _load(args.project, args.max_file_mb)
    indexes = {m.path: SemanticIndex(m) for m in project.models}
    doc = {"type": "scan", "project": project.root, "inventory": build_inventory(project, indexes),
           "parse_issues": to_jsonable([*project.issues, *[i for m in project.models for i in m.issues],
                                        *[i for r in project.reports for i in r.issues]])}
    _emit(doc, args, "scan", [root])
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    project, root = _load(args.project, args.max_file_mb)
    perf, src = (None, "")
    if args.performance:
        perf, src = _load_perf(args.performance, args.max_file_mb)
    doc = run_audit(project, perf, src, {"high_ms": args.high_ms, "medium_ms": args.medium_ms})
    if not args.output:
        print(render(doc, args.format if args.format != "all" else "markdown", args.lang))
        return _fail_code(doc, args.fail_on)
    out = prepare_output_dir(args.output, [root])
    formats = list(FORMATS) if args.format == "all" else [args.format]
    for f in formats:
        name = "findings.json" if f == "json" else f"audit-report{FORMATS[f]}"
        _write(out, name, render(doc, f, args.lang))
        print(f"wrote {name}", file=sys.stderr)
    c = doc["severity_breakdown"]
    print(f"findings: {doc['metrics']['findings_total']} (" + ", ".join(f"{k}={v}" for k, v in c.items()) + ")",
          file=sys.stderr)
    return _fail_code(doc, args.fail_on)


def cmd_performance(args: argparse.Namespace) -> int:
    perf, src = _load_perf(args.input, args.max_file_mb)
    roots = []
    names: dict[str, str] = {}
    if args.project:
        project, root = _load(args.project, args.max_file_mb)
        roots.append(root)
        names = {v.name: f"{r.name}/{p.display_name}/{v.title or v.name}" for r in project.reports
                 for p in r.pages for v in p.visuals}
    findings = performance_findings(perf, src, {"high_ms": args.high_ms, "medium_ms": args.medium_ms}, names)
    doc = {"type": "performance", "project": src, "performance": perf, "findings": to_jsonable(findings),
           "limitations": ["Durations come only from the provided log; 'Other' is derived as total minus measured "
                           "components and includes queueing time."]}
    _emit(doc, args, "performance", roots)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    before, r1 = _load(args.before, args.max_file_mb)
    after, r2 = _load(args.after, args.max_file_mb)
    doc = diff_projects(before, after)
    doc["project"] = f"{before.root} -> {after.root}"
    _emit(doc, args, "change-impact", [r1, r2])
    return 0


def cmd_investigate(args: argparse.Namespace) -> int:
    project, root = _load(args.project, args.max_file_mb)
    models = [m for m in project.models if not args.model or m.name.lower() == args.model.lower()]
    if not models:
        raise ForensicsError("No semantic model found (check --model / project path)", 2)
    model = models[0]
    visual = None
    if args.visual:
        for r in project.reports:
            for v in r.visuals():
                if args.visual.lower() in (v.name.lower(), (v.title or "").lower()):
                    visual = v
        if visual is None:
            raise ForensicsError(f"Visual not found: {args.visual}", 2)
    doc = investigate_filter(SemanticIndex(model), args.from_table, args.to_table, args.measure, visual)
    doc["project"] = project.root
    doc["model"] = model.name
    _emit(doc, args, "investigation", [root])
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    p = Path(args.input).expanduser()
    if not p.is_file():
        raise ForensicsError(f"Input not found: {p}", 2)
    p = p.resolve()
    try:
        doc = read_json(p.parent, p)
    except json.JSONDecodeError as exc:
        raise ForensicsError(f"Input is not valid JSON: {exc}", 2) from exc
    if not isinstance(doc, dict) or "findings" not in doc:
        raise ForensicsError("Input is not a findings.json produced by 'audit'", 2)
    text = render(doc, args.format, args.lang)
    if args.output:
        out = prepare_output_dir(args.output, [])
        name = f"audit-report{FORMATS[args.format]}"
        _write(out, name, text)
        print(f"wrote {name}", file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Auditoria completa em um passo, com relatório HTML e abertura opcional no navegador."""
    excludes = set() if args.no_default_excludes else set(DEFAULT_EXCLUDES)
    excludes |= {x.lower() for x in args.exclude or []}
    doc, files = run_full(args.project, args.performance, args.output, args.lang, excludes,
                          int(args.max_file_mb * 1024 * 1024), auto_perf=not args.no_auto_performance)
    print(console_summary(doc, files), file=sys.stderr)
    if args.open:
        webbrowser.open(files["html"].resolve().as_uri())
    return _fail_code(doc, args.fail_on)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pbip-forensics",
                                     description="Read-only forensics for Power BI PBIP projects.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    parser.add_argument("--debug", action="store_true", help="show internal tracebacks")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser, fmt_default: str = "json", allow_all: bool = False) -> None:
        p.add_argument("--format", choices=[*FORMATS, *(["all"] if allow_all else [])], default=fmt_default)
        p.add_argument("--output", help="output directory (must be outside the audited project)")
        p.add_argument("--lang", choices=["en", "pt-BR"], default="en")
        p.add_argument("--max-file-mb", type=float, default=25.0, help="per-file size limit (MB)")

    p = sub.add_parser("run", help="one-shot audit: everything + HTML report (recommended)")
    p.add_argument("--project", required=True)
    p.add_argument("--performance", help="Performance Analyzer export; auto-detected inside the project if omitted")
    p.add_argument("--no-auto-performance", action="store_true", help="do not search the project for a log")
    p.add_argument("--output", help="output folder (default: <project>-forensics next to the project)")
    p.add_argument("--lang", choices=["en", "pt-BR"], default="en")
    p.add_argument("--open", action="store_true", help="open the HTML report in the default browser")
    p.add_argument("--exclude", action="append", help="folder name to skip (repeatable)")
    p.add_argument("--no-default-excludes", action="store_true",
                   help=f"also scan {', '.join(sorted(DEFAULT_EXCLUDES))}")
    p.add_argument("--fail-on", choices=list(SEVERITY_RANK))
    p.add_argument("--max-file-mb", type=float, default=25.0)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("scan", help="discover and inventory a project")
    p.add_argument("--project", required=True)
    common(p, allow_all=True)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("audit", help="run all static diagnostics")
    p.add_argument("--project", required=True)
    p.add_argument("--performance", help="Performance Analyzer export (.json)")
    p.add_argument("--fail-on", choices=list(SEVERITY_RANK), help="exit 1 if a finding at/above this severity exists")
    p.add_argument("--high-ms", type=float, default=3000.0)
    p.add_argument("--medium-ms", type=float, default=1000.0)
    common(p, fmt_default="all", allow_all=True)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("performance", help="analyze a Performance Analyzer export")
    p.add_argument("--input", required=True)
    p.add_argument("--project", help="optional project to map visual IDs")
    p.add_argument("--high-ms", type=float, default=3000.0)
    p.add_argument("--medium-ms", type=float, default=1000.0)
    common(p, allow_all=True)
    p.set_defaults(func=cmd_performance)

    p = sub.add_parser("diff", help="compare two project versions")
    p.add_argument("--before", required=True)
    p.add_argument("--after", required=True)
    common(p, allow_all=True)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("investigate", help="filter-propagation root-cause investigation")
    p.add_argument("--project", required=True)
    p.add_argument("--from-table", required=True, help="table where the selection/filter is applied")
    p.add_argument("--to-table", help="table expected to be filtered")
    p.add_argument("--measure", help="measure expected to react")
    p.add_argument("--visual", help="visual name or title to include its filters")
    p.add_argument("--model", help="semantic model name when the project has several")
    common(p, allow_all=True)
    p.set_defaults(func=cmd_investigate)

    p = sub.add_parser("report", help="render a findings.json as markdown/html/json")
    p.add_argument("--input", required=True)
    p.add_argument("--format", choices=list(FORMATS), default="markdown")
    p.add_argument("--output")
    p.add_argument("--lang", choices=["en", "pt-BR"], default="en")
    p.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    try:
        return int(args.func(args))
    except ForensicsError as exc:
        _err(str(exc))
        return exc.exit_code
    except (OSError, UnicodeDecodeError) as exc:
        _err(f"{type(exc).__name__}: {exc.strerror if isinstance(exc, OSError) and exc.strerror else exc}")
        return 2
    except Exception as exc:  # erro inesperado: mensagem curta, traceback só com --debug
        if args.debug:
            raise
        _err(f"internal error ({type(exc).__name__}). Re-run with --debug for details.")
        return 10


if __name__ == "__main__":
    raise SystemExit(main())
