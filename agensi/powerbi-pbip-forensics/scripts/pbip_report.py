#!/usr/bin/env python3
"""Power BI PBIP Forensics — pbip_report.py (v1.0.0, Vinicius de Souza Santos).

Standalone, read-only script generated from the modular engine (src/pbip_forensics).
Requires only the Python 3.11+ standard library. Run with --help for usage.
Never modifies the analyzed project; writes only to --output (outside the project).
"""

# Arquivo gerado por tools/build_skill.py — não editar manualmente.
# Módulos incluídos: models, security.safety, entrypoints.common, reporting.merge, reporting.render, entrypoints.ep_report

from __future__ import annotations

import sys

if sys.version_info < (3, 11):  # verificação antes de qualquer import dependente de versão
    sys.stderr.write("error: Python 3.11 or newer is required (found %d.%d)\n" % sys.version_info[:2])
    raise SystemExit(2)

import argparse
import contextlib
import hashlib
import html
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


def safe_walk(root: Path, max_files: int = DEFAULT_MAX_FILES) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    skipped: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept = []
        for d in sorted(dirnames):
            full = current / d
            if d in SKIP_DIRS:
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
# módulo de origem: pbip_forensics.reporting.merge
# ----------------------------------------------------------------------
def merge_documents(docs: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "tool": TOOL_NAME, "version": TOOL_VERSION, "generated_at": "", "project": None,
        "scope": {"project": None, "read_only": True, "performance_log": None, "modules": []},
        "inventory": {}, "findings": [], "dependency_map": [], "performance": None, "change_impact": None,
        "investigations": [], "parse_issues": [], "limitations": [],
    }
    seen: dict[str, dict[str, Any]] = {}
    from_diff = False
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        # O nome do projeto auditado tem prioridade sobre o rótulo "antes -> depois" do diff.
        if doc.get("project") and (merged["project"] is None or (from_diff and doc.get("script") != "diff")):
            merged["project"] = doc["project"]
            from_diff = doc.get("script") == "diff"
        merged["generated_at"] = max(merged["generated_at"], str(doc.get("generated_at") or ""))
        script = doc.get("script") or doc.get("type") or "audit"
        if script not in merged["scope"]["modules"]:
            merged["scope"]["modules"].append(script)
        if doc.get("inventory") and not merged["inventory"]:
            merged["inventory"] = doc["inventory"]
        for f in doc.get("findings", []) or []:
            if isinstance(f, dict) and f.get("id"):
                seen.setdefault(f["id"], f)
        merged["dependency_map"].extend(doc.get("dependency_map", []) or [])
        if doc.get("performance"):
            merged["performance"] = doc["performance"]
            merged["scope"]["performance_log"] = doc.get("performance_source")
        if doc.get("change_impact"):
            merged["change_impact"] = doc["change_impact"]
        merged["investigations"].extend(doc.get("investigations", []) or [])
        for issue in doc.get("parse_issues", []) or []:
            if issue not in merged["parse_issues"]:
                merged["parse_issues"].append(issue)
        for lim in doc.get("limitations", []) or []:
            if lim not in merged["limitations"]:
                merged["limitations"].append(lim)
    status_rank = {s: i for i, s in enumerate(STATUSES)}
    merged["findings"] = sorted(seen.values(), key=lambda f: (SEVERITY_RANK.get(f.get("severity"), 9),
                                                              status_rank.get(f.get("status"), 9), f["id"]))
    sev = Counter(f["severity"] for f in merged["findings"])
    st = Counter(f["status"] for f in merged["findings"])
    merged["severity_breakdown"] = {s: sev.get(s, 0) for s in SEVERITIES}
    merged["status_breakdown"] = {s: st.get(s, 0) for s in STATUSES}
    merged["scope"]["project"] = merged["project"]
    if merged["performance"] is None:
        merged["limitations"].append("No Performance Analyzer log provided: no runtime measurements are available.")
    return merged


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.reporting.render
# ----------------------------------------------------------------------
Block = tuple[Any, ...]

LABELS = {
    "en": {
        "title": "Power BI PBIP Forensics — Audit Report", "exec": "Executive Summary",
        "inventory": "Project Inventory", "scope": "Audit Scope", "overall": "Overall Findings",
        "severity": "Severity Breakdown", "relationships": "Relationship Analysis", "dax": "DAX Analysis",
        "visuals": "Visual Dependencies", "performance": "Performance Analysis", "impact": "Change Impact",
        "hypotheses": "Root Cause Hypotheses", "actions": "Recommended Actions", "limitations": "Limitations",
        "appendix": "Evidence Appendix", "none": "No findings in this section.",
        "no_perf": "No Performance Analyzer log was provided. No runtime measurements are available; the items "
                   "below are static risks that should be measured before acting.",
        "no_impact": "No version comparison was requested for this report.",
        "no_hyp": "No investigation was requested. Use the `investigate` command for question-driven analysis.",
    },
    "pt-BR": {
        "title": "Power BI PBIP Forensics — Relatório de Auditoria", "exec": "Resumo Executivo",
        "inventory": "Inventário do Projeto", "scope": "Escopo da Auditoria", "overall": "Achados Gerais",
        "severity": "Distribuição por Severidade", "relationships": "Análise de Relacionamentos",
        "dax": "Análise DAX", "visuals": "Dependências de Visuais", "performance": "Análise de Desempenho",
        "impact": "Impacto de Alterações", "hypotheses": "Hipóteses de Causa Raiz",
        "actions": "Ações Recomendadas", "limitations": "Limitações", "appendix": "Apêndice de Evidências",
        "none": "Nenhum achado nesta seção.",
        "no_perf": "Nenhum log do Performance Analyzer foi informado. Não há medições reais; os itens abaixo são "
                   "riscos estáticos que devem ser medidos antes de qualquer ação.",
        "no_impact": "Nenhuma comparação de versões foi solicitada.",
        "no_hyp": "Nenhuma investigação foi solicitada. Use o comando `investigate`.",
    },
}

_REL_CATS = {"Relationships", "Model structure"}
_DAX_CATS = {"DAX", "DAX performance", "Filter context"}


def _ftable(findings: list[dict[str, Any]]) -> Block:
    return ("table", ["ID", "Severity", "Status", "Category", "Title"],
            [[f["id"], f["severity"], f["status"], f["category"], f["title"]] for f in findings])


def build_blocks(doc: dict[str, Any], lang: str = "en", max_rows: int = 200) -> list[Block]:
    L = LABELS.get(lang, LABELS["en"])
    findings: list[dict[str, Any]] = doc.get("findings", [])
    inv = doc.get("inventory", {})
    counts = inv.get("counts", {})
    sev = doc.get("severity_breakdown", {})
    st = doc.get("status_breakdown", {})
    b: list[Block] = [("h1", L["title"]),
                      ("p", f"Project: **{doc.get('project')}** · Tool {doc.get('tool')} {doc.get('version')} · "
                            f"Generated (UTC): {doc.get('generated_at')}")]
    # 1. Resumo executivo
    b.append(("h2", L["exec"]))
    top = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    if sev:
        b.append(("p", f"{len(findings)} findings: " + ", ".join(f"{k} {v}" for k, v in sev.items()) +
                  f". Confirmed {st.get('confirmed', 0)}, potential {st.get('potential', 0)}, "
                  f"inconclusive {st.get('inconclusive', 0)}."))
    else:
        b.append(("p", f"{len(findings)} findings produced by this command (full rule set runs with `audit`)."))
    b.append(("p", f"Inventory: {counts.get('reports', 0)} report(s), {counts.get('pages', 0)} page(s), "
                   f"{counts.get('visuals', 0)} visual(s), {counts.get('semantic_models', 0)} model(s), "
                   f"{counts.get('tables', 0)} table(s), {counts.get('measures', 0)} measure(s), "
                   f"{counts.get('relationships', 0)} relationship(s)."))
    if top:
        b.append(("ul", [f"**{f['severity']}/{f['status']}** {f['title']} (`{f['id']}`)" for f in top[:10]]))
    # 2. Inventário
    b.append(("h2", L["inventory"]))
    b.append(("table", ["Item", "Count"], [[k, str(v)] for k, v in counts.items()]))
    for r in inv.get("reports", []):
        b.append(("h3", f"Report: {r['name']} ({r['format']}, support: {r['support']})"))
        b.append(("p", f"Path `{r['path']}` · PBIR version {r.get('pbir_version')} · dataset reference: "
                       f"{r.get('dataset_reference')}"))
        rows = [[p["display_name"], v["title"] or v["name"], v["type"], str(v["field_count"]), str(v["visual_filters"]),
                 "; ".join(v["limitations"])] for p in r["pages"] for v in p["visuals"]]
        b.append(("table", ["Page", "Visual", "Type", "Fields", "Visual filters", "Limitations"], rows[:max_rows]))
    for m in inv.get("models", []):
        b.append(("h3", f"Semantic model: {m['name']} ({m['format']}, support: {m['support']})"))
        b.append(("table", ["Table", "Role", "Columns", "Measures", "Calculated", "Data sources"],
                  [[t["name"], str(t["role"]), str(len(t["columns"])), str(len(t["measures"])),
                    "yes" if t["is_calculated"] else "", ", ".join(t["data_sources"])] for t in m["tables"]]))
    # 3. Escopo
    b.append(("h2", L["scope"]))
    sc = doc.get("scope", {})
    b.append(("ul", [f"Project folder: `{sc.get('project')}` (read-only: {sc.get('read_only')})",
                     f"Modules: {', '.join(sc.get('modules', []))}",
                     f"Performance log: {sc.get('performance_log') or 'not provided'}",
                     f"Skipped items (security/scope): {len(inv.get('skipped_items', []))}"]))
    # 4/5. Achados e severidade
    b.append(("h2", L["overall"]))
    b.append(_ftable(findings) if findings else ("p", L["none"]))
    b.append(("h2", L["severity"]))
    b.append(("table", ["Severity", "Count"], [[k, str(v)] for k, v in sev.items()]))
    b.append(("table", ["Status", "Count"], [[k, str(v)] for k, v in st.items()]))
    # 6. Relacionamentos
    b.append(("h2", L["relationships"]))
    for m in inv.get("models", []):
        b.append(("table", ["From", "To", "Active", "Cross filter", "Cardinality"],
                  [[r["from"], r["to"], str(r["is_active"]), r["cross_filter"], r["cardinality"]]
                   for r in m["relationships"]]))
    rel = [f for f in findings if f["category"] in _REL_CATS]
    b.append(_ftable(rel) if rel else ("p", L["none"]))
    # 7. DAX
    b.append(("h2", L["dax"]))
    dax = [f for f in findings if f["category"] in _DAX_CATS]
    b.append(_ftable(dax) if dax else ("p", L["none"]))
    for m in inv.get("models", []):
        deep = sorted(m["measures"], key=lambda x: -(x.get("depth") or 0))[:15]
        b.append(("table", ["Measure", "Depth", "Depends on"],
                  [[f"[{x['name']}]", str(x.get("depth")), ", ".join(x["measure_dependencies"])] for x in deep]))
    # 8. Visuais
    b.append(("h2", L["visuals"]))
    vis = [f for f in findings if f["category"] == "Visual dependencies"]
    b.append(_ftable(vis) if vis else ("p", L["none"]))
    dm = doc.get("dependency_map", [])
    b.append(("p", f"Dependency map: {len(dm)} bindings (Page → Visual → Field → Table)"
                   + (f"; first {max_rows} shown, full list in JSON." if len(dm) > max_rows else ".")))
    b.append(("table", ["Page", "Visual", "Usage", "Kind", "Table", "Field", "Status"],
              [[d["page"], d["visual_title"] or d["visual"], d["usage"], d["kind"], str(d["table"]), str(d["field"]),
                d["status"]] for d in dm[:max_rows]]))
    # 9. Desempenho
    b.append(("h2", L["performance"]))
    perf = doc.get("performance")
    if perf:
        b.append(("p", f"Log version {perf.get('version')}, {perf.get('event_count')} events, "
                       f"{len(perf.get('visuals', []))} visual lifecycles (sorted by measured total)."))
        b.append(("table", ["Visual", "Type", "Total ms", "DAX ms", "DirectQuery ms", "Display ms", "Other ms"],
                  [[str(v["visual_title"] or v["visual_id"]), str(v["visual_type"]), _n(v["total_ms"]),
                    _n(v["dax_query_ms"]), _n(v["direct_query_ms"]), _n(v["visual_display_ms"]), _n(v["other_ms"])]
                   for v in perf.get("visuals", [])[:max_rows]]))
        if perf.get("warnings"):
            b.append(("ul", perf["warnings"]))
        pf = [f for f in findings if f["category"] == "Performance"]
        b.append(_ftable(pf) if pf else ("p", L["none"]))
    else:
        b.append(("p", L["no_perf"]))
        risks = [f for f in findings if f["category"] == "DAX performance"]
        b.append(_ftable(risks) if risks else ("p", L["none"]))
    # 10. Impacto
    b.append(("h2", L["impact"]))
    ci = doc.get("change_impact")
    if ci:
        b.append(("p", "Summary: " + ", ".join(f"{k} {v}" for k, v in ci["summary"].items()) + ". " + ci["note"]))
        b.append(("table", ["Type", "Object", "Change", "Details"],
                  [[c["object_type"], c["object"], c["change"], "; ".join(c["details"])] for c in ci["changes"]]))
        for imp in ci["impacts"]:
            b.append(("h3", imp["change"]))
            b.append(("p", imp["message"]))
            b.append(("ul", [f"Dependent measure: {x}" for x in imp["dependent_measures"]]
                      + [f"Visual: {x}" for x in imp["affected_visuals"]] or ["No dependents found."]))
    else:
        b.append(("p", L["no_impact"]))
    # 11. Hipóteses
    b.append(("h2", L["hypotheses"]))
    invs = doc.get("investigations", [])
    if invs:
        for inv_ in invs:
            b.append(("h3", f"Investigation: {inv_.get('from_table')} → {', '.join(inv_.get('targets', []))}"
                            + (f" (measure {inv_['measure']})" if inv_.get("measure") else "")))
            b.append(("p", "Deterministic evidence:"))
            b.append(("pre", "\n".join(inv_.get("evidence", []))))
            for h in inv_.get("hypotheses", []):
                b.append(("p", f"**#{h['rank']} [{h['confidence']} confidence]** {h['hypothesis']} — "
                               f"{h['justification']}"))
                b.append(("ul", h["verification_steps"]))
    else:
        b.append(("p", L["no_hyp"]))
    # 12. Ações
    b.append(("h2", L["actions"]))
    seen, actions = set(), []
    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM") and (f["rule_id"], f["recommendation"]) not in seen:
            seen.add((f["rule_id"], f["recommendation"]))
            actions.append(f"[{f['severity']}] {f['rule_id']}: {f['recommendation']}")
    b.append(("ol", actions) if actions else ("p", L["none"]))
    # 13. Limitações
    b.append(("h2", L["limitations"]))
    b.append(("ul", doc.get("limitations", [])))
    # 14. Apêndice
    b.append(("h2", L["appendix"]))
    for f in findings:
        loc = f["path"] + (f":{f['line']}" if f.get("line") else "")
        b.append(("h3", f"{f['id']} — {f['title']}"))
        b.append(("ul", [f"Severity: {f['severity']} · Status: {f['status']} · Category: {f['category']}",
                         f"Source: `{loc}` · Object: `{f['object_ref']}`",
                         f"Explanation: {f['explanation']}", f"Impact: {f['impact']}",
                         f"Recommendation: {f['recommendation']}", f"Verification: {f['verification']}"]))
        b.append(("pre", "\n".join(f["evidence"])))
    return b


def _n(v: Any) -> str:
    return "" if v is None else f"{float(v):.1f}"


def _md_cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(blocks: list[Block]) -> str:
    out: list[str] = []
    for blk in blocks:
        kind = blk[0]
        if kind in ("h1", "h2", "h3"):
            out += [f"{'#' * int(kind[1])} {blk[1]}", ""]
        elif kind == "p":
            out += [blk[1], ""]
        elif kind in ("ul", "ol"):
            out += [f"{i + 1}. {x}" if kind == "ol" else f"- {x}" for i, x in enumerate(blk[1])] + [""]
        elif kind == "pre":
            out += ["```text", blk[1], "```", ""]
        elif kind == "table":
            headers, rows = blk[1], blk[2]
            if not rows:
                out += ["_(empty)_", ""]
                continue
            out.append("| " + " | ".join(headers) + " |")
            out.append("|" + "---|" * len(headers))
            out += ["| " + " | ".join(_md_cell(c) for c in r) + " |" for r in rows] + [""]
    return "\n".join(out).rstrip() + "\n"


def _inline(text: str) -> str:
    esc = html.escape(text)
    parts = esc.split("**")
    esc = "".join(f"<strong>{p}</strong>" if i % 2 else p for i, p in enumerate(parts))
    parts = esc.split("`")
    return "".join(f"<code>{p}</code>" if i % 2 else p for i, p in enumerate(parts))


_CSS = """body{font-family:Segoe UI,Arial,sans-serif;margin:2rem auto;max-width:1200px;padding:0 1rem;color:#1b1b1b}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:.9rem}th,td{border:1px solid #ccc;
padding:4px 6px;text-align:left;vertical-align:top}th{background:#f2f2f2}pre{background:#f7f7f7;padding:.6rem;
overflow:auto;white-space:pre-wrap}h2{border-bottom:2px solid #333;padding-bottom:.2rem;margin-top:2rem}
code{background:#f0f0f0;padding:0 3px}"""


def to_html(blocks: list[Block], lang: str = "en") -> str:
    out = [f'<!doctype html><html lang="{html.escape(lang)}"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           f"<title>{html.escape(str(blocks[0][1]))}</title><style>{_CSS}</style></head><body>"]
    for blk in blocks:
        kind = blk[0]
        if kind in ("h1", "h2", "h3"):
            out.append(f"<{kind}>{_inline(blk[1])}</{kind}>")
        elif kind == "p":
            out.append(f"<p>{_inline(blk[1])}</p>")
        elif kind in ("ul", "ol"):
            out.append(f"<{kind}>" + "".join(f"<li>{_inline(str(x))}</li>" for x in blk[1]) + f"</{kind}>")
        elif kind == "pre":
            out.append(f"<pre>{html.escape(blk[1])}</pre>")
        elif kind == "table":
            if not blk[2]:
                out.append("<p><em>(empty)</em></p>")
                continue
            head = "".join(f"<th>{html.escape(h)}</th>" for h in blk[1])
            rows = "".join("<tr>" + "".join(f"<td>{_inline(str(c))}</td>" for c in r) + "</tr>" for r in blk[2])
            out.append(f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
    out.append("</body></html>")
    return "\n".join(out)


def render(doc: dict[str, Any], fmt: str, lang: str = "en") -> str:
    if fmt == "json":
        return json.dumps(doc, indent=2, ensure_ascii=False)
    blocks = build_blocks(doc, lang)
    if fmt == "markdown":
        return to_markdown(blocks)
    if fmt == "html":
        return to_html(blocks, lang)
    raise ValueError(f"Unknown format: {fmt}")


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.entrypoints.ep_report
# ----------------------------------------------------------------------
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


if __name__ == "__main__":
    raise SystemExit(main())
