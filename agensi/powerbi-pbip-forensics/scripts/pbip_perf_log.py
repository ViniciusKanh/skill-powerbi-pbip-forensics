#!/usr/bin/env python3
"""Power BI PBIP Forensics — pbip_perf_log.py (v1.0.0, Vinicius de Souza Santos).

Standalone, read-only script generated from the modular engine (src/pbip_forensics).
Requires only the Python 3.11+ standard library. Run with --help for usage.
Never modifies the analyzed project; writes only to --output (outside the project).
"""

# Arquivo gerado por tools/build_skill.py — não editar manualmente.
# Módulos incluídos: models, analyzers.performance, security.safety, entrypoints.common, findings.summary, entrypoints.ep_perf_log

from __future__ import annotations

import sys

if sys.version_info < (3, 11):  # verificação antes de qualquer import dependente de versão
    sys.stderr.write("error: Python 3.11 or newer is required (found %d.%d)\n" % sys.version_info[:2])
    raise SystemExit(2)

import argparse
import contextlib
import hashlib
import json
import os
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.models
# ----------------------------------------------------------------------
TOOL_NAME = "powerbi-pbip-forensics"
TOOL_VERSION = "1.0.0"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
STATUSES = ("confirmed", "potential", "inconclusive")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES)}


class ForensicsError(Exception):

    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class ParseIssue:

    path: str
    message: str
    line: int | None = None
    kind: str = "parse-error"


@dataclass
class Column:
    table: str
    name: str
    data_type: str | None = None
    is_hidden: bool = False
    is_calculated: bool = False
    expression: str | None = None
    path: str = ""
    line: int | None = None
    sort_by: str | None = None


@dataclass
class Measure:
    table: str
    name: str
    expression: str = ""
    format_string: str | None = None
    display_folder: str | None = None
    is_hidden: bool = False
    path: str = ""
    line: int | None = None


@dataclass
class Relationship:
    id: str
    from_table: str
    from_column: str
    to_table: str
    to_column: str
    is_active: bool = True
    cross_filter: str = "oneDirection"
    from_cardinality: str = "many"
    to_cardinality: str = "one"
    path: str = ""
    line: int | None = None

    @property
    def is_bidirectional(self) -> bool:
        return self.cross_filter.lower() == "bothdirections"

    def label(self) -> str:
        arrow = "<->" if self.is_bidirectional else "->"
        return (
            f"'{self.from_table}'[{self.from_column}] ({self.from_cardinality}) {arrow} "
            f"'{self.to_table}'[{self.to_column}] ({self.to_cardinality})"
        )


@dataclass
class Table:
    name: str
    path: str = ""
    line: int | None = None
    is_hidden: bool = False
    is_calculated: bool = False
    is_calculation_group: bool = False
    columns: list[Column] = field(default_factory=list)
    measures: list[Measure] = field(default_factory=list)
    hierarchies: list[str] = field(default_factory=list)
    hierarchy_columns: list[str] = field(default_factory=list)
    calc_source: str | None = None  # DAX da tabela calculada (apenas para análise de referências)
    partition_kinds: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)


@dataclass
class SemanticModel:
    name: str
    path: str
    format: str = "unknown"  # tmdl | tmsl | unknown
    support: str = "full"  # full | limited | unsupported
    pbism_version: str | None = None
    tables: list[Table] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    shared_expressions: list[str] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)

    def table(self, name: str) -> Table | None:
        low = name.lower()
        for tbl in self.tables:
            if tbl.name.lower() == low:
                return tbl
        return None

    def all_measures(self) -> list[Measure]:
        return [m for t in self.tables for m in t.measures]


@dataclass
class FieldRef:
    kind: str  # column | measure | aggregation | hierarchyLevel | unknown
    entity: str | None
    property: str | None
    role: str = ""
    usage: str = "projection"  # projection | filter | sort
    detail: str | None = None

    def key(self) -> str:
        return f"{self.entity}[{self.property}]"


@dataclass
class Visual:
    name: str
    page: str
    visual_type: str
    path: str
    title: str | None = None
    is_custom: bool = False
    is_group: bool = False
    fields: list[FieldRef] = field(default_factory=list)
    filter_count: int = 0
    limitations: list[str] = field(default_factory=list)


@dataclass
class Page:
    name: str
    display_name: str
    path: str
    visuals: list[Visual] = field(default_factory=list)
    filters: list[FieldRef] = field(default_factory=list)


@dataclass
class Report:
    name: str
    path: str
    format: str = "unknown"  # pbir | pbir-legacy | unknown
    support: str = "full"
    pbir_version: str | None = None
    dataset_ref: str | None = None  # caminho relativo ou "byConnection"
    model_path: str | None = None
    pages: list[Page] = field(default_factory=list)
    filters: list[FieldRef] = field(default_factory=list)
    extension_measures: list[str] = field(default_factory=list)
    custom_visual_ids: list[str] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)

    def visuals(self) -> list[Visual]:
        return [v for p in self.pages for v in p.visuals]


@dataclass
class Project:
    root: str
    pbip_files: list[str] = field(default_factory=list)
    reports: list[Report] = field(default_factory=list)
    models: list[SemanticModel] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def model_for(self, report: Report) -> SemanticModel | None:
        if report.model_path is None:
            return None
        for model in self.models:
            if model.path == report.model_path:
                return model
        return None


@dataclass
class Finding:

    rule_id: str
    title: str
    category: str
    severity: str
    status: str
    evidence: list[str]
    path: str
    object_ref: str
    explanation: str
    impact: str
    recommendation: str
    verification: str
    line: int | None = None
    confidence_note: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"Severidade inválida: {self.severity}")
        if self.status not in STATUSES:
            raise ValueError(f"Status inválido: {self.status}")
        if not self.id:
            self.id = stable_id(self.rule_id, self.path, self.object_ref)


def stable_id(rule_id: str, path: str, object_ref: str) -> str:
    digest = hashlib.sha1(f"{rule_id}|{path}|{object_ref}".encode(), usedforsecurity=False)
    return f"{rule_id}-{digest.hexdigest()[:8]}"


def to_jsonable(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, list):
        return [to_jsonable(o) for o in obj]
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    return obj


def sort_findings(findings: list[Finding]) -> list[Finding]:
    status_rank = {s: i for i, s in enumerate(STATUSES)}
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], status_rank[f.status], f.id))


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.analyzers.performance
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.security.safety
# ----------------------------------------------------------------------
DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_FILES = 20000

# Diretórios que nunca precisam ser percorridos para a auditoria.
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", ".venv", "venv", "__pycache__", ".pbi", ".idea", ".vs"}

# Padrões de arquivos sensíveis: nunca lidos, apenas contabilizados.
_SENSITIVE_RE = re.compile(
    r"(^\.env(\..*)?$)|(\.(pem|key|pfx|p12|cer|crt|kdbx|ppk)$)|(^id_(rsa|dsa|ecdsa|ed25519))"
    r"|(^(credentials|secrets?)(\..*)?$)|(^localsettings\.json$)|(\.abf$)",
    re.IGNORECASE,
)

# Padrões de redação aplicados a qualquer texto que vá para relatórios.
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(password|pwd|user id|uid|accountkey|sharedaccesskey|client_secret|secret|token|apikey|api_key)"
                r"\s*=\s*[^;\"'\s]+"), r"\1=<redacted>"),
    (re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"), "Bearer <redacted>"),
    (re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*"), "<redacted-jwt>"),
    (re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1<redacted>@"),
    (re.compile(r"(?i)(sig|signature)=[a-z0-9%+/=]{16,}"), r"\1=<redacted>"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE_RE.search(name))


def resolve_root(path: str | os.PathLike[str]) -> Path:
    raw = Path(path).expanduser()
    if not raw.exists():
        raise ForensicsError(f"Path not found: {raw}", exit_code=2)
    if not raw.is_dir():
        raise ForensicsError(f"Not a directory: {raw}", exit_code=2)
    return raw.resolve()


def is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root)
    except (ValueError, OSError):
        return False
    return True


def rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.name


def safe_walk(root: Path, max_files: int = DEFAULT_MAX_FILES,
              exclude_dirs: set[str] | None = None) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    skipped: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept = []
        for d in sorted(dirnames):
            full = current / d
            if d in SKIP_DIRS:
                continue
            if exclude_dirs and d.lower() in exclude_dirs:
                skipped.append(f"excluded-by-option: {rel(root, current)}/{d}")
                continue
            if full.is_symlink() and not is_within(root, full):
                skipped.append(f"symlink-outside-scope: {rel(root, current)}/{d}")
                continue
            if full.is_symlink():
                # Links internos também não são seguidos (evita ciclos).
                skipped.append(f"symlink-not-followed: {rel(root, current)}/{d}")
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in sorted(filenames):
            full = current / name
            if is_sensitive_name(name):
                skipped.append(f"sensitive-file-not-read: {rel(root, full)}")
                continue
            if full.is_symlink() and not is_within(root, full):
                skipped.append(f"symlink-outside-scope: {rel(root, current)}/{name}")
                continue
            files.append(full)
            if len(files) > max_files:
                raise ForensicsError(f"File limit exceeded ({max_files}). Narrow the project path.", 3)
    return files, skipped


def read_text(root: Path, path: Path, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> str:
    if not is_within(root, path):
        raise ForensicsError(f"Refusing to read outside authorized scope: {path.name}", 4)
    if is_sensitive_name(path.name):
        raise ForensicsError(f"Refusing to read sensitive file: {path.name}", 4)
    size = path.stat().st_size
    if size > max_bytes:
        raise ForensicsError(f"File too large ({size} bytes > limit {max_bytes}): {rel(root, path)}", 3)
    data = path.read_bytes()
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        # Alguns exports antigos usam UTF-16 com BOM.
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return data.decode("utf-16")
        raise


def read_json(root: Path, path: Path, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> Any:
    return json.loads(read_text(root, path, max_bytes))


def prepare_output_dir(output: str | os.PathLike[str], forbidden_roots: list[Path]) -> Path:
    out = Path(output).expanduser().resolve()
    for root in forbidden_roots:
        if out == root or is_within(root, out):
            raise ForensicsError(
                "Output directory must be outside the audited project (read-only policy).", 4
            )
    out.mkdir(parents=True, exist_ok=True)
    return out


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.entrypoints.common
# ----------------------------------------------------------------------
def skill_parser(description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--output", help="output directory (outside the audited project); default: print JSON")
    p.add_argument("--max-file-mb", type=float, default=25.0, help="per-file size limit in MB")
    return p


def skill_header(script: str, project: str | None) -> dict[str, Any]:
    return {"tool": TOOL_NAME, "version": TOOL_VERSION, "script": script, "project": project,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds")}


def skill_emit(doc: dict[str, Any], output: str | None, filename: str, roots: list[Path]) -> None:
    text = json.dumps(doc, indent=2, ensure_ascii=False)
    if output:
        out = prepare_output_dir(output, roots)
        (out / filename).write_text(text, encoding="utf-8", newline="\n")
        counts = doc.get("severity_breakdown") or {}
        summary = ", ".join(f"{k}={v}" for k, v in counts.items())
        print(f"wrote {filename}" + (f" (findings: {summary})" if summary else ""), file=sys.stderr)
    else:
        print(text)


def skill_run(fn: Callable[[list[str] | None], int], argv: list[str] | None = None) -> int:
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    try:
        return fn(argv)
    except ForensicsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except (OSError, UnicodeDecodeError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # erro inesperado: sem traceback para o usuário final
        print(f"error: internal error ({type(exc).__name__})", file=sys.stderr)
        return 10


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.findings.summary
# ----------------------------------------------------------------------
def finalize(findings: list[Finding]) -> dict[str, Any]:
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.id, f)
    ordered = sort_findings(list(unique.values()))
    sev = Counter(f.severity for f in ordered)
    st = Counter(f.status for f in ordered)
    return {"findings": to_jsonable(ordered),
            "severity_breakdown": {s: sev.get(s, 0) for s in SEVERITIES},
            "status_breakdown": {s: st.get(s, 0) for s in STATUSES}}


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.entrypoints.ep_perf_log
# ----------------------------------------------------------------------
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


if __name__ == "__main__":
    raise SystemExit(main())
