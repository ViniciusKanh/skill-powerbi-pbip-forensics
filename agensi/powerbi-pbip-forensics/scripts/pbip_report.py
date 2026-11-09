#!/usr/bin/env python3
"""Power BI PBIP Forensics — pbip_report.py (v1.0.0, Vinicius de Souza Santos).

Standalone, read-only script generated from the modular engine (src/pbip_forensics).
Requires only the Python 3.11+ standard library. Run with --help for usage.
Never modifies the analyzed project; writes only to --output (outside the project).
"""

# Arquivo gerado por tools/build_skill.py — não editar manualmente.
# Módulos incluídos: models, security.safety, entrypoints.common, reporting.merge, reporting.insights, reporting.html_report, reporting.render, entrypoints.ep_report

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
import math
import os
import re
from collections import Counter, defaultdict
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
# módulo de origem: pbip_forensics.reporting.insights
# ----------------------------------------------------------------------
SEV_WEIGHT = {"CRITICAL": 20.0, "HIGH": 8.0, "MEDIUM": 3.0, "LOW": 1.0, "INFO": 0.0}
STATUS_FACTOR = {"confirmed": 1.0, "potential": 0.5, "inconclusive": 0.25}
SCORE_SCALE = 40.0  # nota = 100 * exp(-penalidade / 40)

AREAS = [
    ("model", {"Relationships", "Model structure"}),
    ("dax", {"DAX", "DAX performance", "Filter context"}),
    ("visuals", {"Visual dependencies"}),
    ("performance", {"Performance"}),
    ("files", {"Parsing"}),
]

INS_LABELS = {
    "en": {
        "model": "Data model", "dax": "DAX measures", "visuals": "Report & visuals", "performance": "Performance",
        "files": "Project files", "good": "Good", "attention": "Needs attention", "critical": "Critical",
        "not_measured": "Not measured", "quick": "Quick win", "medium": "Medium effort", "structural": "Structural",
    },
    "pt-BR": {
        "model": "Modelo de dados", "dax": "Medidas DAX", "visuals": "Relatório e visuais",
        "performance": "Desempenho", "files": "Arquivos do projeto", "good": "Bom", "attention": "Requer atenção",
        "critical": "Crítico", "not_measured": "Não medido", "quick": "Ganho rápido", "medium": "Esforço médio",
        "structural": "Estrutural",
    },
}

# Título em linguagem simples, esforço típico e público de cada regra.
PLAIN: dict[str, tuple[str, str, str]] = {
    # regra: (esforço, en, pt)
    "VIS001": ("quick", "Fix visuals bound to tables that no longer exist",
               "Corrigir visuais ligados a tabelas que não existem mais"),
    "VIS002": ("quick", "Fix visuals bound to removed or renamed fields",
               "Corrigir visuais ligados a campos removidos ou renomeados"),
    "DAX001": ("quick", "Fix measures that reference missing objects",
               "Corrigir medidas que apontam para objetos inexistentes"),
    "DAX002": ("medium", "Break circular dependencies between measures", "Eliminar dependência circular entre medidas"),
    "DAX007": ("quick", "Fix USERELATIONSHIP/CROSSFILTER without a relationship",
               "Corrigir USERELATIONSHIP/CROSSFILTER sem relacionamento"),
    "DAX013": ("quick", "Fill in empty measures", "Preencher medidas vazias"),
    "MOD001": ("quick", "Fix relationships pointing to missing columns",
               "Corrigir relacionamentos com colunas inexistentes"),
    "MOD006": ("structural", "Remove ambiguous filter paths between tables",
               "Eliminar caminhos de filtro ambíguos entre tabelas"),
    "MOD003": ("medium", "Review bidirectional relationships", "Revisar relacionamentos bidirecionais"),
    "MOD004": ("structural", "Review many-to-many relationships", "Revisar relacionamentos muitos-para-muitos"),
    "MOD002": ("medium", "Review inactive relationships", "Revisar relacionamentos inativos"),
    "MOD007": ("quick", "Align data types of relationship keys", "Alinhar tipos de dados das chaves"),
    "MOD008": ("medium", "Connect or remove isolated tables", "Conectar ou remover tabelas isoladas"),
    "MOD009": ("quick", "Turn off Auto date/time and use a date table",
               "Desligar data/hora automática e usar tabela calendário"),
    "MOD010": ("quick", "Hide foreign-key columns on fact tables", "Ocultar chaves estrangeiras das tabelas fato"),
    "VIS005": ("medium", "Fix visuals whose grouping cannot filter the measure",
               "Corrigir visuais cujo agrupamento não filtra a medida"),
    "VIS006": ("medium", "Fix tables combining unrelated data", "Corrigir tabelas que combinam dados sem relação"),
    "VIS007": ("medium", "Review page filters that do not reach the measures",
               "Revisar filtros de página que não chegam às medidas"),
    "VIS008": ("medium", "Reduce the number of visuals on heavy pages", "Reduzir a quantidade de visuais por página"),
    "VIS003": ("medium", "Review visuals the tool could not interpret",
               "Revisar visuais que a ferramenta não conseguiu interpretar"),
    "DAX003": ("medium", "Replace FILTER over whole tables with column filters",
               "Trocar FILTER sobre tabela inteira por filtros de coluna"),
    "DAX004": ("medium", "Simplify nested iterators", "Simplificar iteradores aninhados"),
    "DAX005": ("medium", "Avoid measure calls per row of fact tables", "Evitar medidas por linha em tabelas fato"),
    "DAX009": ("quick", "Use DIVIDE instead of '/'", "Usar DIVIDE em vez de '/'"),
    "DAX010": ("quick", "Remove IFERROR/ISERROR", "Remover IFERROR/ISERROR"),
    "DAX011": ("quick", "Clean up unused measures", "Limpar medidas não utilizadas"),
    "DAX014": ("quick", "Set format strings on numeric measures", "Definir formato nas medidas numéricas"),
    "COL001": ("quick", "Remove unused columns to shrink the model", "Remover colunas sem uso para reduzir o modelo"),
    "PERF001": ("medium", "Speed up the slowest visuals", "Acelerar os visuais mais lentos"),
    "PRS001": ("quick", "Fix files that could not be read", "Corrigir arquivos que não puderam ser lidos"),
}
EFFORT_RANK = {"quick": 0, "medium": 1, "structural": 2}
_VALUE_INFO_RULES = {"DAX011", "COL001", "MOD009", "DAX014", "MOD010"}


def _grade(score: int | None) -> str:
    if score is None:
        return "not_measured"
    return "good" if score >= 85 else "attention" if score >= 65 else "critical"


def scores(findings: list[dict[str, Any]], has_perf: bool) -> dict[str, Any]:
    areas: list[dict[str, Any]] = []
    for key, cats in AREAS:
        fs = [f for f in findings if f.get("category") in cats]
        if key == "performance" and not has_perf:
            areas.append({"key": key, "score": None, "grade": "not_measured", "findings": len(fs)})
            continue
        penalty = sum(SEV_WEIGHT.get(f["severity"], 0) * STATUS_FACTOR.get(f["status"], 0.5) for f in fs)
        sc = round(100 * math.exp(-penalty / SCORE_SCALE))
        areas.append({"key": key, "score": sc, "grade": _grade(sc), "findings": len(fs),
                      "penalty": round(penalty, 1)})
    valid: list[int] = [a["score"] for a in areas if a["score"] is not None and a["key"] != "files"]
    overall = round(sum(valid) / len(valid)) if valid else None
    return {"overall": overall, "grade": _grade(overall), "areas": areas,
            "formula": "score = 100 × exp(−Σ weight(severity) × factor(status) / 40); weights CRITICAL 20, HIGH 8, "
                       "MEDIUM 3, LOW 1, INFO 0; factors confirmed 1, potential 0.5, inconclusive 0.25."}


def quick_wins(findings: list[dict[str, Any]], lang: str, limit: int = 8) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        if f["severity"] != "INFO" or f["rule_id"] in _VALUE_INFO_RULES:
            groups[f["rule_id"]].append(f)
    sev_rank = {s: i for i, s in enumerate(SEV_WEIGHT)}
    out = []
    for rid, fs in groups.items():
        effort, en, pt = PLAIN.get(rid, ("medium", fs[0]["title"], fs[0]["title"]))
        worst = min((f["severity"] for f in fs), key=lambda s: sev_rank[s])
        out.append({"rule_id": rid, "title": pt if lang == "pt-BR" else en, "effort": effort, "severity": worst,
                    "count": len(fs), "confirmed": sum(1 for f in fs if f["status"] == "confirmed"),
                    "recommendation": fs[0]["recommendation"]})
    out.sort(key=lambda a: (sev_rank[a["severity"]] if a["severity"] in ("CRITICAL", "HIGH") else 5,
                            EFFORT_RANK[a["effort"]], sev_rank[a["severity"]], -a["count"]))
    return out[:limit]


def narrative(doc: dict[str, Any], lang: str) -> list[str]:
    pt = lang == "pt-BR"
    fs = doc.get("findings", []) or []
    c = (doc.get("inventory") or {}).get("counts", {}) or {}
    by = Counter(f["rule_id"] for f in fs)
    conf = Counter(f["rule_id"] for f in fs if f["status"] == "confirmed")
    s: list[str] = []
    if c:
        s.append((f"O projeto tem {c.get('pages', 0)} páginas com {c.get('visuals', 0)} visuais, apoiadas em "
                  f"{c.get('tables', 0)} tabelas, {c.get('relationships', 0)} relacionamentos e "
                  f"{c.get('measures', 0)} medidas.") if pt else
                 (f"The project has {c.get('pages', 0)} pages with {c.get('visuals', 0)} visuals, built on "
                  f"{c.get('tables', 0)} tables, {c.get('relationships', 0)} relationships and "
                  f"{c.get('measures', 0)} measures."))
    broken = conf["VIS001"] + conf["VIS002"]
    if broken:
        s.append(f"{broken} vínculo(s) de visual usam campos que não existem mais: esses visuais exibem erro."
                 if pt else f"{broken} visual binding(s) use fields that no longer exist: those visuals show an error.")
    dax_err = conf["DAX001"] + conf["DAX002"] + conf["DAX007"] + conf["DAX013"]
    if dax_err:
        s.append(f"{dax_err} problema(s) confirmados em fórmulas DAX impedem medidas de calcular."
                 if pt else f"{dax_err} confirmed DAX formula problem(s) prevent measures from calculating.")
    if by["MOD006"]:
        s.append("Existem caminhos de filtro ambíguos entre tabelas: alguns números podem depender de qual caminho o "
                 "Power BI escolhe. É o principal ponto estrutural a revisar." if pt else
                 "There are ambiguous filter paths between tables: some numbers may depend on which path Power BI "
                 "uses. This is the main structural point to review.")
    filt = by["VIS005"] + by["VIS006"] + by["VIS007"]
    if filt:
        s.append(f"{filt} visual(is)/filtro(s) podem não filtrar como o usuário espera (ex.: linhas repetindo o total "
                 "ou dados sem relação)." if pt else
                 f"{filt} visual(s)/filter(s) may not filter as users expect (e.g., rows repeating the total or "
                 "unrelated data).")
    perf = doc.get("performance")
    slow = [f for f in fs if f["rule_id"] == "PERF001"]
    if perf and slow:
        s.append(f"No log de desempenho, {len(slow)} visual(is) passaram do limite de tempo; o mais lento foi "
                 f"“{slow[0]['title'].split(': ', 1)[-1]}”." if pt else
                 f"In the performance log, {len(slow)} visual(s) exceeded the time threshold; the slowest was "
                 f"“{slow[0]['title'].split(': ', 1)[-1]}”.")
    elif not perf:
        s.append("Não foi informado log do Performance Analyzer, então não há medição real de lentidão; existem "
                 f"{by['DAX003'] + by['DAX004'] + by['DAX005']} padrões DAX que merecem medição." if pt else
                 "No Performance Analyzer log was provided, so slowness was not measured; there are "
                 f"{by['DAX003'] + by['DAX004'] + by['DAX005']} DAX patterns worth measuring.")
    cleanup = by["DAX011"]
    cols = sum(int(f["title"].split("(")[-1].split(" ")[0]) for f in fs if f["rule_id"] == "COL001"
               and f["title"].split("(")[-1].split(" ")[0].isdigit())
    if cleanup or cols:
        s.append(f"Oportunidade de limpeza: {cleanup} medida(s) e {cols} coluna(s) sem uso detectado."
                 if pt else f"Clean-up opportunity: {cleanup} measure(s) and {cols} column(s) with no detected use.")
    if not broken and not dax_err and not by["MOD006"] and not filt:
        s.append("Nenhum problema estrutural grave foi encontrado nos arquivos." if pt else
                 "No serious structural problem was found in the files.")
    return s


def model_graph(doc: dict[str, Any]) -> dict[str, Any]:
    models = (doc.get("inventory") or {}).get("models", []) or []
    if not models:
        return {"nodes": [], "edges": [], "hidden_auto": 0}
    m = models[0]
    auto = [t for t in m["tables"] if t["name"].startswith(("LocalDateTable_", "DateTableTemplate_"))]
    nodes = [{"name": t["name"], "role": t.get("role") or "disconnected", "columns": len(t["columns"]),
              "measures": len(t["measures"]), "calculated": t.get("is_calculated", False)}
             for t in m["tables"] if t not in auto]
    names = {n["name"] for n in nodes}
    amb_ids: set[str] = set()
    for f in doc.get("findings", []) or []:
        if f["rule_id"] == "MOD006" and f["severity"] == "HIGH" and "/cycle/" in f.get("object_ref", ""):
            amb_ids |= set(f["object_ref"].split("/cycle/", 1)[1].split("+"))
    edges = []
    for r in m.get("relationships", []):
        ft, tt = r["from"].split("'[")[0].strip("'"), r["to"].split("'[")[0].strip("'")
        if ft in names and tt in names:
            edges.append({"id": r["id"], "from": ft, "to": tt, "active": r["is_active"],
                          "both": str(r["cross_filter"]).lower() == "bothdirections", "card": r["cardinality"],
                          "ambiguous": r["id"] in amb_ids, "label": f"{r['from']} → {r['to']}"})
    return {"nodes": nodes, "edges": edges, "hidden_auto": len(auto), "model": m["name"]}


def measure_stats(doc: dict[str, Any]) -> dict[str, Any]:
    models = (doc.get("inventory") or {}).get("models", []) or []
    measures = [x for m in models for x in m.get("measures", [])]
    used_in_visuals = Counter(d["field"] for d in doc.get("dependency_map", []) or [] if d.get("kind") == "measure")
    referenced = Counter(dep for x in measures for dep in x.get("measure_dependencies", []))
    complex_top = sorted((x for x in measures if x.get("complexity")),
                         key=lambda x: -x["complexity"]["score"])[:10]
    hubs = sorted(measures, key=lambda x: -(referenced[x["name"]] * 2 + used_in_visuals[x["name"]]))[:10]
    folders = Counter((x.get("display_folder") or "—") for x in measures)
    return {
        "total": len(measures),
        "no_format": sum(1 for x in measures if not x.get("format_string")),
        "no_folder": sum(1 for x in measures if not x.get("display_folder")),
        "max_depth": max((x.get("depth") or 0 for x in measures), default=0),
        "complex": [{"name": x["name"], "table": x["table"], **x["complexity"], "depth": x.get("depth"),
                     "used_by_measures": referenced[x["name"]], "used_in_visuals": used_in_visuals[x["name"]]}
                    for x in complex_top],
        "hubs": [{"name": x["name"], "used_by_measures": referenced[x["name"]],
                  "used_in_visuals": used_in_visuals[x["name"]]} for x in hubs
                 if referenced[x["name"]] or used_in_visuals[x["name"]]],
        "folders": folders.most_common(12),
    }


def page_stats(doc: dict[str, Any]) -> list[dict[str, Any]]:
    reports = (doc.get("inventory") or {}).get("reports", []) or []
    dm = doc.get("dependency_map", []) or []
    fs = doc.get("findings", []) or []
    out = []
    for r in reports:
        for p in r.get("pages", []):
            vis = p.get("visuals", [])
            pdm = [d for d in dm if d.get("page") == p["display_name"] and d.get("report", r["name"]) == r["name"]]
            sev = Counter(f["severity"] for f in fs if p.get("path") and str(f.get("path", "")).startswith(p["path"]))
            out.append({
                "report": r["name"], "page": p["display_name"], "visuals": len(vis),
                "data_visuals": sum(1 for v in vis if v.get("field_count")),
                "slicers": sum(1 for v in vis if "slicer" in str(v.get("type", "")).lower()),
                "custom": sum(1 for v in vis if v.get("is_custom")),
                "filters": len(p.get("page_filters", [])) + sum(v.get("visual_filters", 0) for v in vis),
                "measures": len({d["field"] for d in pdm if d.get("kind") == "measure"}),
                "tables": sorted({d["table"] for d in pdm if d.get("table") and d.get("kind") != "measure"}),
                "broken": sum(1 for d in pdm if d.get("status") not in ("ok", "unknown")),
                "findings": dict(sev),
            })
    return out


def data_sources(doc: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for m in (doc.get("inventory") or {}).get("models", []) or []:
        for t in m.get("tables", []):
            for s in t.get("data_sources", []):
                out[s].append(t["name"])
    return dict(out)


def compute_insights(doc: dict[str, Any], lang: str = "en") -> dict[str, Any]:
    fs = doc.get("findings", []) or []
    labels = INS_LABELS.get(lang, INS_LABELS["en"])
    sc = scores(fs, bool(doc.get("performance")))
    for a in sc["areas"]:
        a["label"] = labels[a["key"]]
        a["grade_label"] = labels[a["grade"]]
    sc["grade_label"] = labels[sc["grade"]]
    wins = quick_wins(fs, lang)
    for w in wins:
        w["effort_label"] = labels[w["effort"]]
    return {"scores": sc, "narrative": narrative(doc, lang), "quick_wins": wins, "model_graph": model_graph(doc),
            "measures": measure_stats(doc), "pages": page_stats(doc), "sources": data_sources(doc)}


# ----------------------------------------------------------------------
# módulo de origem: pbip_forensics.reporting.html_report
# ----------------------------------------------------------------------
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
STATUS_ORDER = ["confirmed", "potential", "inconclusive"]

T = {
    "en": {
        "title": "Audit Report", "summary": "Summary", "priorities": "Top priorities", "rules": "Rules overview",
        "findings": "Findings", "relationships": "Relationships", "dax": "DAX", "visuals": "Visuals",
        "performance": "Performance", "impact": "Change impact", "hypotheses": "Root cause", "actions": "Actions",
        "limitations": "Limitations", "inventory": "Inventory", "search": "Search title, object, path or evidence…",
        "all_status": "All statuses", "all_cat": "All categories", "all_rules": "All rules", "expand": "Expand all",
        "collapse": "Collapse all", "showing": "Showing", "of": "of", "explanation": "Explanation",
        "impact_l": "Impact", "recommendation": "Recommendation", "verification": "How to verify",
        "evidence": "Evidence", "source": "Source", "none": "Nothing to show in this section.",
        "no_perf": "No Performance Analyzer log was provided. No runtime measurements are available; static "
                   "performance risks are listed in Findings (category “DAX performance”).",
        "no_impact": "No version comparison was run. Use the diff command/script to compare two versions.",
        "no_hyp": "No investigation was run. Use investigate (CLI) or pbip_visual_deps.py --from-table … to get "
                  "ranked root-cause hypotheses.",
        "total": "Findings", "confirmed": "confirmed", "potential": "potential", "inconclusive": "inconclusive",
        "count": "Count", "rule": "Rule", "category": "Category", "max_sev": "Highest", "example": "Example",
        "status": "Status", "generated": "Generated (UTC)", "readonly": "Read-only analysis",
        "applies": "applies to", "items": "finding(s)", "bindings": "bindings", "broken": "Problem bindings",
        "full_map": "Full dependency map", "measure": "Measure", "depth": "Depth", "depends": "Depends on",
        "from": "From", "to": "To", "active": "Active", "cross": "Cross filter", "card": "Cardinality",
        "visual": "Visual", "type": "Type", "total_ms": "Total ms", "page": "Page", "field": "Field",
        "table": "Table", "kind": "Kind", "usage": "Usage", "rank": "Rank", "conf": "confidence",
        "steps": "Verification steps", "det_evidence": "Deterministic evidence", "dependents": "Dependent measures",
        "affected": "Affected visuals", "changes": "Changes", "object": "Object", "change": "Change",
        "details": "Details", "footer": "Static analysis: DAX is not executed and no data values are read. "
                                         "Findings marked potential require verification in Power BI.",
        "filter_rule": "Filter findings by this rule",
        "overview": "Overview", "health": "Health score", "plain": "In plain words", "wins": "What to do first",
        "model_map": "Model map", "measures_t": "Measures", "pages_t": "Pages", "sources": "Data sources",
        "score_note": "Indicative score from the findings (not a quality certificate). Formula: ",
        "legend_dim": "Dimension", "legend_fact": "Fact", "legend_bridge": "Bridge", "legend_disc": "Disconnected",
        "legend_inactive": "inactive", "legend_both": "bidirectional", "legend_amb": "ambiguous path",
        "auto_hidden": "auto date tables hidden", "complex_t": "Most complex measures", "hubs_t": "Central measures",
        "folders_t": "Display folders", "score": "Score", "calls": "Functions", "iters": "Iterators",
        "nest": "Nesting", "used_m": "Used by measures", "used_v": "Used in visuals", "data_vis": "data visuals",
        "slicers": "slicers", "custom": "custom", "filters": "filters", "measures_l": "measures",
        "broken_l": "broken bindings", "tables_l": "Tables used", "no_fmt": "without format",
        "no_folder": "without folder", "max_depth": "max dependency depth", "effort": "Effort",
    },
    "pt-BR": {
        "title": "Relatório de Auditoria", "summary": "Resumo", "priorities": "Prioridades", "rules": "Visão por regra",
        "findings": "Achados", "relationships": "Relacionamentos", "dax": "DAX", "visuals": "Visuais",
        "performance": "Desempenho", "impact": "Impacto de mudanças", "hypotheses": "Causa raiz", "actions": "Ações",
        "limitations": "Limitações", "inventory": "Inventário", "search": "Buscar título, objeto, caminho ou evidência…",
        "all_status": "Todos os status", "all_cat": "Todas as categorias", "all_rules": "Todas as regras",
        "expand": "Expandir tudo", "collapse": "Recolher tudo", "showing": "Exibindo", "of": "de",
        "explanation": "Explicação", "impact_l": "Impacto", "recommendation": "Recomendação",
        "verification": "Como verificar", "evidence": "Evidências", "source": "Origem",
        "none": "Nada a exibir nesta seção.",
        "no_perf": "Nenhum log do Performance Analyzer foi informado. Não há medições reais; os riscos estáticos de "
                   "desempenho estão em Achados (categoria “DAX performance”).",
        "no_impact": "Nenhuma comparação de versões foi executada. Use o comando/script diff.",
        "no_hyp": "Nenhuma investigação foi executada. Use investigate (CLI) ou pbip_visual_deps.py --from-table … "
                  "para obter hipóteses ordenadas.",
        "total": "Achados", "confirmed": "confirmados", "potential": "potenciais", "inconclusive": "inconclusivos",
        "count": "Qtde", "rule": "Regra", "category": "Categoria", "max_sev": "Maior", "example": "Exemplo",
        "status": "Status", "generated": "Gerado (UTC)", "readonly": "Análise somente leitura",
        "applies": "aplica-se a", "items": "achado(s)", "bindings": "vínculos", "broken": "Vínculos com problema",
        "full_map": "Mapa completo de dependências", "measure": "Medida", "depth": "Profundidade",
        "depends": "Depende de", "from": "De", "to": "Para", "active": "Ativo", "cross": "Filtro cruzado",
        "card": "Cardinalidade", "visual": "Visual", "type": "Tipo", "total_ms": "Total ms", "page": "Página",
        "field": "Campo", "table": "Tabela", "kind": "Tipo", "usage": "Uso", "rank": "Posição", "conf": "confiança",
        "steps": "Passos de verificação", "det_evidence": "Evidência determinística",
        "dependents": "Medidas dependentes", "affected": "Visuais afetados", "changes": "Mudanças",
        "object": "Objeto", "change": "Mudança", "details": "Detalhes",
        "footer": "Análise estática: DAX não é executado e nenhum dado é lido. Achados potenciais exigem "
                  "verificação no Power BI.",
        "filter_rule": "Filtrar achados por esta regra",
        "overview": "Visão geral", "health": "Nota de saúde", "plain": "Em palavras simples",
        "wins": "O que fazer primeiro", "model_map": "Mapa do modelo", "measures_t": "Medidas", "pages_t": "Páginas",
        "sources": "Fontes de dados",
        "score_note": "Nota indicativa calculada a partir dos achados (não é certificado de qualidade). Fórmula: ",
        "legend_dim": "Dimensão", "legend_fact": "Fato", "legend_bridge": "Ponte", "legend_disc": "Desconectada",
        "legend_inactive": "inativo", "legend_both": "bidirecional", "legend_amb": "caminho ambíguo",
        "auto_hidden": "tabelas automáticas de data ocultas", "complex_t": "Medidas mais complexas",
        "hubs_t": "Medidas centrais", "folders_t": "Pastas de exibição", "score": "Pontuação", "calls": "Funções",
        "iters": "Iteradores", "nest": "Aninhamento", "used_m": "Usada por medidas", "used_v": "Usada em visuais",
        "data_vis": "visuais com dados", "slicers": "segmentações", "custom": "personalizados", "filters": "filtros",
        "measures_l": "medidas", "broken_l": "vínculos quebrados", "tables_l": "Tabelas usadas",
        "no_fmt": "sem formato", "no_folder": "sem pasta", "max_depth": "profundidade máx. de dependência",
        "effort": "Esforço",
    },
}

_LOGO = ('<svg viewBox="0 0 64 64" width="40" height="40" aria-hidden="true"><path d="M32 3 7 12v18c0 15 '
         '10.5 26.5 25 31 14.5-4.5 25-16 25-31V12z" fill="var(--brand)"/><rect x="17" y="18" width="30" height="22" '
         'rx="3" fill="#fff"/><rect x="21" y="30" width="4" height="7" fill="#F2A900"/><rect x="27" y="26" width="4" '
         'height="11" fill="#F2A900"/><rect x="33" y="22" width="4" height="15" fill="#F2A900"/><circle cx="41" '
         'cy="41" r="7" fill="none" stroke="#0B1F44" stroke-width="3"/><path d="m46 46 6 6" stroke="#F2A900" '
         'stroke-width="4" stroke-linecap="round"/></svg>')

_CSS = """
:root{--bg:#f5f7fb;--panel:#fff;--ink:#14213d;--muted:#5b6478;--line:#e3e7ef;--brand:#0b5ed7;--brand2:#f2a900;
--crit:#7a0b2e;--high:#d1242f;--med:#d97706;--low:#2563eb;--info:#64748b;--ok:#15803d;--chip:#eef2f8;
--shadow:0 1px 2px rgba(16,24,40,.06),0 2px 8px rgba(16,24,40,.06)}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--panel:#161b22;--ink:#e6edf3;--muted:#9aa4b2;
--line:#2a313c;--chip:#1f2630;--shadow:none}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
a{color:var(--brand)}code,pre{font-family:Consolas,"Cascadia Mono",Menlo,monospace;font-size:12.5px}
header.top{background:linear-gradient(120deg,#0b1f44,#0b5ed7);color:#fff;padding:22px 28px 18px}
.top .row{display:flex;gap:14px;align-items:center;flex-wrap:wrap}.top h1{margin:0;font-size:22px}
.top .sub{opacity:.85;font-size:13px}.meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.meta span{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.25);border-radius:999px;
padding:3px 10px;font-size:12px}
nav.tabs{position:sticky;top:0;z-index:5;background:var(--panel);border-bottom:1px solid var(--line);
display:flex;gap:2px;overflow-x:auto;padding:0 18px;box-shadow:var(--shadow)}
nav.tabs a{padding:11px 12px;text-decoration:none;color:var(--muted);white-space:nowrap;font-weight:600;
border-bottom:3px solid transparent}nav.tabs a:hover{color:var(--ink);border-color:var(--brand2)}
main{max-width:1280px;margin:0 auto;padding:22px 20px 60px}
section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;
margin-bottom:18px;box-shadow:var(--shadow);scroll-margin-top:56px}
h2{font-size:17px;margin:0 0 12px;display:flex;align-items:center;gap:8px}
h2 .n{background:var(--chip);color:var(--muted);border-radius:999px;font-size:12px;padding:1px 9px}
h3{font-size:14px;margin:16px 0 8px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.kpi{border:1px solid var(--line);border-radius:10px;padding:10px 12px;border-top:4px solid var(--info)}
.kpi b{display:block;font-size:24px;line-height:1.2}.kpi span{color:var(--muted);font-size:12px;text-transform:uppercase;
letter-spacing:.03em}
.kpi.CRITICAL{border-top-color:var(--crit)}.kpi.HIGH{border-top-color:var(--high)}.kpi.MEDIUM{border-top-color:var(--med)}
.kpi.LOW{border-top-color:var(--low)}.kpi.total{border-top-color:var(--brand)}
.stack{display:flex;height:12px;border-radius:999px;overflow:hidden;background:var(--chip);margin:14px 0 6px}
.stack i{display:block}.legend{display:flex;flex-wrap:wrap;gap:12px;color:var(--muted);font-size:12px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;vertical-align:middle}
.bg-CRITICAL{background:var(--crit)}.bg-HIGH{background:var(--high)}.bg-MEDIUM{background:var(--med)}
.bg-LOW{background:var(--low)}.bg-INFO{background:var(--info)}
.inv{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin-top:14px}
.inv div{background:var(--chip);border-radius:8px;padding:8px 10px}.inv b{display:block;font-size:18px}
.inv span{font-size:12px;color:var(--muted)}
.badge{display:inline-block;border-radius:6px;padding:1px 7px;font-size:11px;font-weight:700;color:#fff;
letter-spacing:.02em;white-space:nowrap}
.st{display:inline-block;border-radius:6px;padding:0 7px;font-size:11px;border:1px solid var(--line);color:var(--muted)}
.st.confirmed{border-color:var(--ok);color:var(--ok)}.st.inconclusive{border-style:dashed}
.rule{font-family:Consolas,Menlo,monospace;font-size:12px;color:var(--muted)}
.prio{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:10px}
.prio .card{border:1px solid var(--line);border-left:4px solid var(--high);border-radius:10px;padding:10px 12px}
.prio .card.CRITICAL{border-left-color:var(--crit)}.prio .card p{margin:6px 0 0;color:var(--muted);font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:7px 9px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;background:var(--chip);
position:sticky;top:44px}tbody tr:hover{background:var(--chip)}
.scroll{max-height:520px;overflow:auto;border:1px solid var(--line);border-radius:8px}.scroll th{top:0}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.toolbar input,.toolbar select{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:8px;
padding:7px 10px;font:inherit}.toolbar input{flex:1 1 260px}
.chipbtn{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:999px;padding:5px 11px;
cursor:pointer;font:inherit;font-size:12px;font-weight:600}.chipbtn[aria-pressed=false]{opacity:.45}
.btn{border:1px solid var(--line);background:var(--chip);color:var(--ink);border-radius:8px;padding:6px 11px;cursor:pointer;
font:inherit;font-size:12px}.count{color:var(--muted);font-size:12px;margin-left:auto}
.finding{border:1px solid var(--line);border-left:4px solid var(--info);border-radius:10px;margin-bottom:8px;
background:var(--panel)}.finding.CRITICAL{border-left-color:var(--crit)}.finding.HIGH{border-left-color:var(--high)}
.finding.MEDIUM{border-left-color:var(--med)}.finding.LOW{border-left-color:var(--low)}
.finding summary{list-style:none;cursor:pointer;padding:10px 12px;display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.finding summary::-webkit-details-marker{display:none}.finding summary .t{font-weight:600;flex:1 1 420px}
.finding .body{padding:0 14px 12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}
.finding .body div{background:var(--chip);border-radius:8px;padding:8px 10px}.finding .body h4{margin:0 0 3px;font-size:11px;
text-transform:uppercase;color:var(--muted);letter-spacing:.04em}.finding .body .wide{grid-column:1/-1}
.finding ul{margin:0;padding-left:18px}.src{color:var(--muted);font-size:12px;word-break:break-all}
.perfrow{display:grid;grid-template-columns:minmax(160px,260px) 1fr 80px;gap:10px;align-items:center;margin:6px 0}
.perfbar{display:flex;height:14px;border-radius:4px;overflow:hidden;background:var(--chip)}
.p-dax{background:#0b5ed7}.p-dq{background:#7c3aed}.p-vis{background:#f2a900}.p-oth{background:#94a3b8}
.hyp{border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:8px 0}
.conf{font-size:11px;font-weight:700;border-radius:6px;padding:1px 7px;color:#fff}.conf.high{background:var(--high)}
.conf.medium{background:var(--med)}.conf.low{background:var(--info)}
pre{background:var(--chip);border-radius:8px;padding:10px;white-space:pre-wrap;word-break:break-word;margin:6px 0}
.notice{background:var(--chip);border-left:4px solid var(--brand2);border-radius:8px;padding:10px 12px;color:var(--muted)}
ol.actions li{margin:6px 0}.muted{color:var(--muted)}footer{text-align:center;color:var(--muted);font-size:12px;padding:20px}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--high);font-weight:600}
.gauges{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.gauge{border:1px solid var(--line);border-radius:12px;padding:12px;text-align:center}.gauge svg{display:block;margin:0 auto}.gauge text{fill:var(--ink)}
.gauge .lbl{font-weight:600;margin-top:6px}.gauge .g{font-size:12px;color:var(--muted)}
.gauge.main{background:linear-gradient(180deg,var(--chip),transparent)}
.g-good{stroke:#15803d}.g-attention{stroke:#d97706}.g-critical{stroke:#d1242f}.g-not_measured{stroke:#94a3b8}
.story{font-size:15px;line-height:1.6}.story li{margin:6px 0}
.wins{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px}
.win{border:1px solid var(--line);border-radius:10px;padding:10px 12px}.win h4{margin:4px 0 6px;font-size:14px}
.eff{font-size:11px;font-weight:700;border-radius:6px;padding:1px 7px;background:var(--chip);color:var(--ink)}
.eff.quick{background:#dcfce7;color:#166534}.eff.medium{background:#fef3c7;color:#92400e}.eff.structural{background:#fee2e2;color:#991b1b}
.diagram{overflow:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel)}
.diagram text{font-family:"Segoe UI",system-ui,sans-serif;fill:var(--ink)}
.pages{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}
.pg{border:1px solid var(--line);border-radius:10px;padding:10px 12px}.pg h4{margin:0 0 6px}
.pg .nums{display:flex;flex-wrap:wrap;gap:6px}.pg .nums span{background:var(--chip);border-radius:6px;padding:1px 7px;font-size:12px}
.hbar{display:grid;grid-template-columns:minmax(120px,240px) 1fr 40px;gap:8px;align-items:center;margin:4px 0;font-size:13px}
.hbar div{height:10px;border-radius:4px;background:var(--brand)}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(480px,100%),1fr));gap:16px}.two>div{min-width:0}.two td:first-child{min-width:170px}
@media print{nav.tabs,.toolbar{display:none}body{background:#fff}section{box-shadow:none;break-inside:avoid-page}
th{position:static}.scroll{max-height:none;overflow:visible}}
"""

_JS = """
(function(){
var q=document.getElementById('q'),st=document.getElementById('fst'),ca=document.getElementById('fcat'),
ru=document.getElementById('frule'),cnt=document.getElementById('cnt'),items=[].slice.call(document.querySelectorAll('.finding')),
sev={};[].forEach.call(document.querySelectorAll('.chipbtn[data-sev]'),function(b){sev[b.dataset.sev]=true;
b.addEventListener('click',function(){sev[b.dataset.sev]=!sev[b.dataset.sev];b.setAttribute('aria-pressed',sev[b.dataset.sev]);apply();});});
function apply(){var t=(q.value||'').toLowerCase(),n=0;items.forEach(function(e){var ok=sev[e.dataset.sev]&&
(!st.value||e.dataset.status===st.value)&&(!ca.value||e.dataset.cat===ca.value)&&(!ru.value||e.dataset.rule===ru.value)&&
(!t||e.dataset.text.indexOf(t)>=0);e.style.display=ok?'':'none';if(ok)n++;});cnt.textContent=n;}
[q,st,ca,ru].forEach(function(e){e.addEventListener('input',apply);});
document.getElementById('exp').addEventListener('click',function(){items.forEach(function(e){if(e.style.display!=='none')e.open=true;});});
document.getElementById('col').addEventListener('click',function(){items.forEach(function(e){e.open=false;});});
[].forEach.call(document.querySelectorAll('[data-rulefilter]'),function(a){a.addEventListener('click',function(){
ru.value=a.dataset.rulefilter;apply();});});
window.addEventListener('beforeprint',function(){items.forEach(function(e){e.open=true;});});apply();})();
"""


def e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _badge(sev: str) -> str:
    return f'<span class="badge bg-{e(sev)}">{e(sev)}</span>'


def _table(headers: list[str], rows: list[list[str]], raw: bool = False, scroll: bool = True) -> str:
    if not rows:
        return ""
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c if raw else e(c)}</td>" for c in r) + "</tr>" for r in rows)
    tbl = f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
    return f'<div class="scroll">{tbl}</div>' if scroll else tbl


def _section(sid: str, title: str, content: str, count: int | None = None) -> str:
    n = f' <span class="n">{count}</span>' if count is not None else ""
    return f'<section id="{sid}"><h2>{e(title)}{n}</h2>{content}</section>'


def _finding_card(f: dict[str, Any], L: dict[str, str]) -> str:
    loc = f"{f.get('path', '')}" + (f":{f['line']}" if f.get("line") else "")
    text = " ".join([f.get("title", ""), f.get("object_ref", ""), loc, *f.get("evidence", [])]).lower()
    ev = "".join(f"<li>{e(x)}</li>" for x in f.get("evidence", []))
    return (
        f'<details class="finding {e(f["severity"])}" data-sev="{e(f["severity"])}" data-status="{e(f["status"])}" '
        f'data-cat="{e(f.get("category"))}" data-rule="{e(f.get("rule_id"))}" data-text="{e(text)}">'
        f'<summary>{_badge(f["severity"])} <span class="st {e(f["status"])}">{e(f["status"])}</span> '
        f'<span class="t">{e(f["title"])}</span><span class="rule">{e(f["id"])}</span></summary>'
        f'<div class="body"><div class="wide"><h4>{e(L["source"])}</h4><span class="src">{e(loc)} · '
        f'{e(f.get("object_ref"))}</span></div>'
        f'<div class="wide"><h4>{e(L["evidence"])}</h4><ul>{ev}</ul></div>'
        f'<div><h4>{e(L["explanation"])}</h4>{e(f.get("explanation"))}</div>'
        f'<div><h4>{e(L["impact_l"])}</h4>{e(f.get("impact"))}</div>'
        f'<div><h4>{e(L["recommendation"])}</h4>{e(f.get("recommendation"))}</div>'
        f'<div><h4>{e(L["verification"])}</h4>{e(f.get("verification"))}</div></div></details>'
    )


def _gauge(score: int | None, grade: str, label: str, grade_label: str, main: bool = False) -> str:
    r, c = 34, 2 * 3.14159 * 34
    val = 0 if score is None else max(0, min(100, score))
    txt = "–" if score is None else str(score)
    return (f'<div class="gauge{" main" if main else ""}"><svg width="96" height="96" viewBox="0 0 96 96" '
            f'role="img" aria-label="{e(label)} {e(txt)}"><circle cx="48" cy="48" r="{r}" fill="none" '
            f'stroke="var(--chip)" stroke-width="10"/><circle class="g-{e(grade)}" cx="48" cy="48" r="{r}" '
            f'fill="none" stroke-width="10" stroke-linecap="round" stroke-dasharray="{c * val / 100:.1f} {c:.1f}" '
            f'transform="rotate(-90 48 48)"/><text x="48" y="55" text-anchor="middle" font-size="22" '
            f'font-weight="700">{e(txt)}</text></svg><div class="lbl">{e(label)}</div>'
            f'<div class="g">{e(grade_label)}</div></div>')


def _diagram(g: dict[str, Any], L: dict[str, str]) -> str:
    nodes = g.get("nodes", [])
    if not nodes:
        return ""
    layer_of = {"dimension": 0, "bridge": 1, "fact": 2, "disconnected": 3}
    layers: dict[int, list[str]] = {}
    for n in sorted(nodes, key=lambda n: n["name"].lower()):
        layers.setdefault(layer_of.get(n["role"], 3), []).append(n["name"])
    nbr: dict[str, set[str]] = {n["name"]: set() for n in nodes}
    for ed in g.get("edges", []):
        nbr[ed["from"]].add(ed["to"])
        nbr[ed["to"]].add(ed["from"])
    W, H, GX, GY, PAD = 178, 46, 26, 96, 20
    for _ in range(4):  # ordenação por baricentro (reduz cruzamentos)
        pos = {name: i for row in layers.values() for i, name in enumerate(row)}
        for k in sorted(layers):
            layers[k].sort(key=lambda nm: (sum(pos[x] for x in nbr[nm]) / len(nbr[nm])) if nbr[nm] else 1e9)
    width = max(len(r) for r in layers.values()) * (W + GX) + PAD * 2
    xy: dict[str, tuple[float, float]] = {}
    for row_i, k in enumerate(sorted(layers)):
        row = layers[k]
        off = (width - len(row) * (W + GX) + GX) / 2
        for i, nm in enumerate(row):
            xy[nm] = (off + i * (W + GX), PAD + row_i * (H + GY))
    height = PAD * 2 + len(layers) * (H + GY) - GY
    colors = {"dimension": "#0b5ed7", "fact": "#f2a900", "bridge": "#7c3aed", "disconnected": "#94a3b8"}
    svg = [f'<svg width="{width:.0f}" height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" '
           'xmlns="http://www.w3.org/2000/svg"><defs>'
           '<marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
           '<path d="M0 0L10 5L0 10z" fill="#64748b"/></marker>'
           '<marker id="arO" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
           '<path d="M0 0L10 5L0 10z" fill="#d97706"/></marker></defs>']
    for ed in g.get("edges", []):
        (x1, y1), (x2, y2) = xy[ed["to"]], xy[ed["from"]]  # filtro: lado "one" (to) → lado "many" (from)
        ax, ay, bx, by = x1 + W / 2, y1 + H / 2, x2 + W / 2, y2 + H / 2
        if y1 < y2:
            ay, by = y1 + H, y2
        elif y1 > y2:
            ay, by = y1, y2 + H
        else:
            ay = by = y1 + H
        mid = (ay + by) / 2 if y1 != y2 else ay + 40
        color = "#d1242f" if ed["ambiguous"] else "#d97706" if ed["both"] else "#64748b"
        dash = ' stroke-dasharray="6 5"' if not ed["active"] else ""
        mk = "arO" if ed["both"] and not ed["ambiguous"] else "ar"
        start = f' marker-start="url(#{mk})"' if ed["both"] else ""
        svg.append(f'<path d="M{ax:.0f} {ay:.0f} C {ax:.0f} {mid:.0f}, {bx:.0f} {mid:.0f}, {bx:.0f} {by:.0f}" '
                   f'fill="none" stroke="{color}" stroke-width="{3 if ed["ambiguous"] else 1.6}"{dash}'
                   f' marker-end="url(#{mk})"{start} opacity="{0.45 if not ed["active"] else 0.9}">'
                   f'<title>{e(ed["label"])} · {e(ed["card"])}{" · inactive" if not ed["active"] else ""}</title></path>')
    for n in nodes:
        x, y = xy[n["name"]]
        name = n["name"] if len(n["name"]) <= 24 else n["name"][:23] + "…"
        svg.append(f'<g><title>{e(n["name"])} · {e(n["role"])} · {n["columns"]} cols · {n["measures"]} measures</title>'
                   f'<rect x="{x:.0f}" y="{y:.0f}" width="{W}" height="{H}" rx="8" fill="var(--panel)" '
                   f'stroke="{colors.get(n["role"], "#94a3b8")}" stroke-width="2"/>'
                   f'<rect x="{x:.0f}" y="{y:.0f}" width="6" height="{H}" rx="3" fill="{colors.get(n["role"], "#94a3b8")}"/>'
                   f'<text x="{x + 14:.0f}" y="{y + 19:.0f}" font-size="12.5" font-weight="600">{e(name)}</text>'
                   f'<text x="{x + 14:.0f}" y="{y + 36:.0f}" font-size="11" opacity=".7">{n["columns"]} cols · '
                   f'{n["measures"]} meas.{" · calc" if n["calculated"] else ""}</text></g>')
    svg.append("</svg>")
    legend = (f'<div class="legend"><span><i class="dot" style="background:#0b5ed7"></i>{e(L["legend_dim"])}</span>'
              f'<span><i class="dot" style="background:#7c3aed"></i>{e(L["legend_bridge"])}</span>'
              f'<span><i class="dot" style="background:#f2a900"></i>{e(L["legend_fact"])}</span>'
              f'<span><i class="dot" style="background:#94a3b8"></i>{e(L["legend_disc"])}</span>'
              f'<span>- - - {e(L["legend_inactive"])}</span><span style="color:#d97706">⇄ {e(L["legend_both"])}</span>'
              f'<span style="color:#d1242f">━ {e(L["legend_amb"])}</span>'
              + (f'<span>· {g["hidden_auto"]} {e(L["auto_hidden"])}</span>' if g.get("hidden_auto") else "")
              + "</div>")
    return legend + f'<div class="diagram">{"".join(svg)}</div>'


def _overview(ins: dict[str, Any], L: dict[str, str]) -> str:
    sc = ins["scores"]
    gauges = _gauge(sc["overall"], sc["grade"], L["health"], sc["grade_label"], True) + "".join(
        _gauge(a["score"], a["grade"], a["label"], a["grade_label"]) for a in sc["areas"])
    story = "".join(f"<li>{e(x)}</li>" for x in ins["narrative"])
    wins = "".join(
        f'<div class="win"><span class="eff {e(w["effort"])}">{e(w["effort_label"])}</span> {_badge(w["severity"])} '
        f'<span class="rule">{e(w["rule_id"])} · {w["count"]}×</span><h4>{e(w["title"])}</h4>'
        f'<div class="muted">{e(w["recommendation"])}</div>'
        f'<a href="#findings" data-rulefilter="{e(w["rule_id"])}">→ {e(L["findings"])}</a></div>'
        for w in ins["quick_wins"])
    return (f'<div class="gauges">{gauges}</div><p class="muted" style="font-size:12px">{e(L["score_note"])}'
            f'{e(sc["formula"])}</p><h3>{e(L["plain"])}</h3><ul class="story">{story}</ul>'
            + (f'<h3>{e(L["wins"])}</h3><div class="wins">{wins}</div>' if wins else ""))


def _measures(ins: dict[str, Any], L: dict[str, str]) -> str:
    ms = ins["measures"]
    if not ms["total"]:
        return f'<p class="muted">{e(L["none"])}</p>'
    chips = (f'<p><b>{ms["total"]}</b> {e(L["measures_l"])} · {ms["no_format"]} {e(L["no_fmt"])} · '
             f'{ms["no_folder"]} {e(L["no_folder"])} · {e(L["max_depth"])}: {ms["max_depth"]}</p>')
    cx = _table([L["measure"], L["score"], L["calls"], L["iters"], L["nest"], L["depth"], L["used_m"], L["used_v"]],
                [[f"[{x['name']}]", str(x["score"]), str(x["calls"]), str(x["iterators"]), str(x["max_nesting"]),
                  str(x["depth"]), str(x["used_by_measures"]), str(x["used_in_visuals"])] for x in ms["complex"]])
    hubs = _table([L["measure"], L["used_m"], L["used_v"]],
                  [[f"[{x['name']}]", str(x["used_by_measures"]), str(x["used_in_visuals"])] for x in ms["hubs"]])
    mx = max((c for _, c in ms["folders"]), default=1)
    folders = "".join(f'<div class="hbar"><span>{e(f)}</span><div style="width:{100 * c / mx:.0f}%"></div>'
                      f'<b>{c}</b></div>' for f, c in ms["folders"])
    return (chips + f'<div class="two"><div><h3>{e(L["complex_t"])}</h3>{cx}</div>'
            f'<div><h3>{e(L["hubs_t"])}</h3>{hubs}<h3>{e(L["folders_t"])}</h3>{folders}</div></div>')


def _pages(ins: dict[str, Any], L: dict[str, str]) -> str:
    cards = []
    for p in ins["pages"]:
        sev = " ".join(f'{_badge(k)} {v}' for k, v in sorted(p["findings"].items(), key=lambda kv: SEV_ORDER.index(kv[0]))
                       if k != "INFO")
        cards.append(
            f'<div class="pg"><h4>{e(p["page"])}</h4><div class="nums"><span>{p["visuals"]} {e(L["visuals"]).lower()}'
            f'</span><span>{p["data_visuals"]} {e(L["data_vis"])}</span><span>{p["slicers"]} {e(L["slicers"])}</span>'
            f'<span>{p["filters"]} {e(L["filters"])}</span><span>{p["measures"]} {e(L["measures_l"])}</span>'
            + (f'<span>{p["custom"]} {e(L["custom"])}</span>' if p["custom"] else "")
            + (f'<span class="bad">{p["broken"]} {e(L["broken_l"])}</span>' if p["broken"] else "")
            + f'</div><p class="muted" style="margin:6px 0 0">{e(L["tables_l"])}: {e(", ".join(p["tables"]) or "—")}</p>'
            + (f"<div>{sev}</div>" if sev else "") + "</div>")
    return f'<div class="pages">{"".join(cards)}</div>' if cards else ""


def to_html_report(doc: dict[str, Any], lang: str = "en") -> str:
    L = T.get(lang, T["en"])
    findings: list[dict[str, Any]] = doc.get("findings", []) or []
    inv = doc.get("inventory", {}) or {}
    counts = inv.get("counts", {}) or {}
    sev = Counter(f["severity"] for f in findings)
    st = Counter(f["status"] for f in findings)
    total = len(findings)
    scope = doc.get("scope", {}) or {}
    ins = compute_insights(doc, lang)
    parts: list[str] = [_section("overview", L["overview"], _overview(ins, L))]

    # ---------------------------------------------------------------- resumo
    kpis = f'<div class="kpi total"><b>{total}</b><span>{e(L["total"])}</span></div>' + "".join(
        f'<div class="kpi {s}"><b>{sev.get(s, 0)}</b><span>{s}</span></div>' for s in SEV_ORDER)
    stack = "".join(f'<i class="bg-{s}" style="width:{100 * sev.get(s, 0) / total:.2f}%"></i>'
                    for s in SEV_ORDER if total and sev.get(s)) if total else ""
    legend = " ".join(f'<span><i class="dot bg-{s}"></i>{s} {sev.get(s, 0)}</span>' for s in SEV_ORDER)
    stx = " · ".join(f"{st.get(s, 0)} {e(L[s])}" for s in STATUS_ORDER)
    inv_cards = "".join(f'<div><b>{e(v)}</b><span>{e(k.replace("_", " "))}</span></div>' for k, v in counts.items())
    parts.append(_section("summary", L["summary"],
                          f'<div class="kpis">{kpis}</div><div class="stack">{stack}</div>'
                          f'<div class="legend">{legend}<span>· {stx}</span></div><div class="inv">{inv_cards}</div>'))

    # ----------------------------------------------------------- prioridades
    prio = sorted([f for f in findings if f["severity"] in ("CRITICAL", "HIGH")],
                  key=lambda f: (SEV_ORDER.index(f["severity"]), STATUS_ORDER.index(f["status"])))[:9]
    if prio:
        cards = "".join(
            f'<div class="card {e(f["severity"])}">{_badge(f["severity"])} <span class="st {e(f["status"])}">'
            f'{e(f["status"])}</span> <span class="rule">{e(f["rule_id"])}</span><div><b>{e(f["title"])}</b></div>'
            f'<p>{e(f.get("recommendation"))}</p></div>' for f in prio)
        parts.append(_section("priorities", L["priorities"], f'<div class="prio">{cards}</div>'))

    # --------------------------------------------------------- visão por regra
    by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        by_rule[f["rule_id"]].append(f)
    rule_rows = []
    for rid, items in sorted(by_rule.items(), key=lambda kv: (min(SEV_ORDER.index(x["severity"]) for x in kv[1]),
                                                              -len(kv[1]), kv[0])):
        worst = min((x["severity"] for x in items), key=SEV_ORDER.index)
        mix = Counter(x["status"] for x in items)
        rule_rows.append([
            f'<a href="#findings" data-rulefilter="{e(rid)}" title="{e(L["filter_rule"])}"><code>{e(rid)}</code></a>',
            e(items[0].get("category")), _badge(worst), str(len(items)),
            e(", ".join(f"{v} {k}" for k, v in mix.items())), e(items[0]["title"])])
    parts.append(_section("rules", L["rules"], _table([L["rule"], L["category"], L["max_sev"], L["count"],
                                                       L["status"], L["example"]], rule_rows, raw=True)
                          or f'<p class="muted">{e(L["none"])}</p>', len(by_rule)))

    # ------------------------------------------------------------- achados
    cats = sorted({f.get("category", "") for f in findings})
    toolbar = (
        f'<div class="toolbar"><input id="q" type="search" placeholder="{e(L["search"])}" aria-label="search">'
        + "".join(f'<button class="chipbtn" type="button" data-sev="{s}" aria-pressed="true">'
                  f'<i class="dot bg-{s}"></i>{s}</button>' for s in SEV_ORDER)
        + f'<select id="fst"><option value="">{e(L["all_status"])}</option>'
        + "".join(f'<option value="{s}">{e(s)}</option>' for s in STATUS_ORDER) + "</select>"
        + f'<select id="fcat"><option value="">{e(L["all_cat"])}</option>'
        + "".join(f'<option value="{e(c)}">{e(c)}</option>' for c in cats) + "</select>"
        + f'<select id="frule"><option value="">{e(L["all_rules"])}</option>'
        + "".join(f'<option value="{e(r)}">{e(r)}</option>' for r in sorted(by_rule)) + "</select>"
        + f'<button class="btn" id="exp" type="button">{e(L["expand"])}</button>'
        + f'<button class="btn" id="col" type="button">{e(L["collapse"])}</button>'
        + f'<span class="count">{e(L["showing"])} <b id="cnt">{total}</b> {e(L["of"])} {total}</span></div>')
    cards = "".join(_finding_card(f, L) for f in findings) or f'<p class="muted">{e(L["none"])}</p>'
    parts.append(_section("findings", L["findings"], toolbar + cards, total))

    # ------------------------------------------------------ relacionamentos
    rel_html = ""
    for m in inv.get("models", []) or []:
        rows = [[e(r["from"]), e(r["to"]),
                 '<span class="ok">✓</span>' if r["is_active"] else '<span class="bad">inactive</span>',
                 ("⇄ " if str(r["cross_filter"]).lower() == "bothdirections" else "→ ") + e(r["cross_filter"]),
                 e(r["cardinality"])] for r in m.get("relationships", [])]
        rel_html += f"<h3>{e(m['name'])}</h3>" + _table([L["from"], L["to"], L["active"], L["cross"], L["card"]],
                                                       rows, raw=True)
    parts.append(_section("relationships", L["model_map"], _diagram(ins["model_graph"], L)
                          + (f"<details><summary><b>{e(L['relationships'])}</b></summary>{rel_html}</details>"
                             if rel_html else "")))

    # ------------------------------------------------------------------ DAX
    dax_html = ""
    for m in inv.get("models", []) or []:
        deep = sorted(m.get("measures", []), key=lambda x: -(x.get("depth") or 0))[:20]
        dax_html += _table([L["measure"], L["depth"], L["depends"]],
                           [[f"[{x['name']}]", str(x.get("depth")), ", ".join(x.get("measure_dependencies", []))]
                            for x in deep])
    parts.append(_section("dax", L["measures_t"], _measures(ins, L) or dax_html))

    # -------------------------------------------------------------- visuais
    dm = doc.get("dependency_map", []) or []
    bad = [d for d in dm if d.get("status") != "ok"]
    vis_html = _pages(ins, L) + f'<p class="muted">{len(dm)} {e(L["bindings"])}</p>'
    if bad:
        vis_html += f"<h3>{e(L['broken'])}</h3>" + _table(
            [L["page"], L["visual"], L["usage"], L["kind"], L["table"], L["field"], L["status"]],
            [[d["page"], d.get("visual_title") or d["visual"], d["usage"], d["kind"], d["table"], d["field"],
              f'{d["status"]}: {d.get("detail")}'] for d in bad])
    if dm:
        vis_html += (f"<details><summary><b>{e(L['full_map'])}</b></summary>" + _table(
            [L["page"], L["visual"], L["type"], L["usage"], L["kind"], L["table"], L["field"], L["status"]],
            [[d["page"], d.get("visual_title") or d["visual"], d["visual_type"], d["usage"], d["kind"], d["table"],
              d["field"], d["status"]] for d in dm[:2000]]) + "</details>")
    parts.append(_section("visuals", L["visuals"], vis_html))

    # ---------------------------------------------------------- desempenho
    perf = doc.get("performance")
    if perf and perf.get("visuals"):
        mx = max((v.get("total_ms") or 0) for v in perf["visuals"]) or 1
        perf_rows: list[str] = []
        for v in perf["visuals"]:
            segs = "".join(f'<i class="{c}" style="width:{100 * (v.get(k) or 0) / mx:.2f}%" title="{k}: '
                           f'{(v.get(k) or 0):.0f} ms"></i>' for k, c in (("dax_query_ms", "p-dax"),
                           ("direct_query_ms", "p-dq"), ("visual_display_ms", "p-vis"), ("other_ms", "p-oth")))
            perf_rows.append(f'<div class="perfrow"><span>{e(v.get("visual_title") or v.get("visual_id"))} '
                        f'<span class="muted">({e(v.get("visual_type"))})</span></span><div class="perfbar">{segs}'
                        f'</div><b>{(v.get("total_ms") or 0):.0f} ms</b></div>')
        legend = ('<div class="legend"><span><i class="dot p-dax"></i>DAX query</span><span><i class="dot p-dq"></i>'
                  'Direct query</span><span><i class="dot p-vis"></i>Visual display</span><span><i class="dot p-oth">'
                  '</i>Other</span></div>')
        warn = "".join(f"<li>{e(w)}</li>" for w in perf.get("warnings", []))
        parts.append(_section("performance", L["performance"], legend + "".join(perf_rows)
                              + (f"<ul class='muted'>{warn}</ul>" if warn else "")))
    else:
        parts.append(_section("performance", L["performance"], f'<p class="notice">{e(L["no_perf"])}</p>'))

    # ------------------------------------------------------------- impacto
    ci = doc.get("change_impact")
    if ci:
        chips = " · ".join(f"{e(k)}: <b>{e(v)}</b>" for k, v in ci.get("summary", {}).items())
        imp = "".join(
            f'<div class="hyp"><b>{e(i["change"])}</b><p>{e(i["message"])}</p>'
            + (f'<p class="muted">{e(L["dependents"])}: {e(", ".join(i["dependent_measures"]))}</p>'
               if i["dependent_measures"] else "")
            + ("<ul>" + "".join(f"<li>{e(x)}</li>" for x in i["affected_visuals"]) + "</ul>"
               if i["affected_visuals"] else "") + "</div>" for i in ci.get("impacts", []))
        parts.append(_section("impact", L["impact"], f"<p>{chips}</p><p class='notice'>{e(ci.get('note'))}</p>"
                              + _table([L["type"], L["object"], L["change"], L["details"]],
                                       [[c["object_type"], c["object"], c["change"], "; ".join(c["details"])]
                                        for c in ci.get("changes", [])]) + imp))
    else:
        parts.append(_section("impact", L["impact"], f'<p class="notice">{e(L["no_impact"])}</p>'))

    # ------------------------------------------------------------ hipóteses
    invs = doc.get("investigations", []) or []
    if invs:
        hy = ""
        for iv in invs:
            hy += (f"<h3>{e(iv.get('from_table'))} → {e(', '.join(iv.get('targets', [])))}"
                   + (f" · [{e(iv['measure'])}]" if iv.get("measure") else "") + "</h3>"
                   + f"<b>{e(L['det_evidence'])}</b><pre>{e(chr(10).join(iv.get('evidence', [])))}</pre>")
            for h in iv.get("hypotheses", []):
                steps = "".join(f"<li>{e(s)}</li>" for s in h.get("verification_steps", []))
                hy += (f'<div class="hyp"><b>#{e(h.get("rank"))}</b> <span class="conf {e(h["confidence"])}">'
                       f'{e(h["confidence"])} {e(L["conf"])}</span> <b>{e(h["hypothesis"])}</b>'
                       f'<p class="muted">{e(h["justification"])}</p><ol>{steps}</ol></div>')
        parts.append(_section("hypotheses", L["hypotheses"], hy, len(invs)))
    else:
        parts.append(_section("hypotheses", L["hypotheses"], f'<p class="notice">{e(L["no_hyp"])}</p>'))

    # --------------------------------------------------------------- ações
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM"):
            groups[(f["rule_id"], f["recommendation"])].append(f)
    acts = sorted(groups.items(), key=lambda kv: (min(SEV_ORDER.index(x["severity"]) for x in kv[1]), -len(kv[1])))
    act_html = "".join(
        f'<li>{_badge(min((x["severity"] for x in v), key=SEV_ORDER.index))} <code>{e(k[0])}</code> {e(k[1])} '
        f'<span class="muted">({e(L["applies"])} {len(v)} {e(L["items"])})</span></li>' for k, v in acts)
    parts.append(_section("actions", L["actions"], f'<ol class="actions">{act_html}</ol>' if act_html
                          else f'<p class="muted">{e(L["none"])}</p>'))

    # ----------------------------------------------------------- limitações
    lims = "".join(f"<li>{e(x)}</li>" for x in doc.get("limitations", []) or [])
    parts.append(_section("limitations", L["limitations"], f"<ul>{lims}</ul>"))

    # ----------------------------------------------------------- inventário
    inv_html = ""
    for r in inv.get("reports", []) or []:
        inv_html += f"<h3>{e(r['name'])} <span class='muted'>({e(r['format'])}, {e(r['support'])})</span></h3>"
        inv_html += _table([L["page"], L["visual"], L["type"], L["field"], "Limitations"],
                           [[p["display_name"], v["title"] or v["name"], v["type"], str(v["field_count"]),
                             "; ".join(v["limitations"])] for p in r["pages"] for v in p["visuals"]])
    for m in inv.get("models", []) or []:
        inv_html += f"<h3>{e(m['name'])} <span class='muted'>({e(m['format'])}, {e(m['support'])})</span></h3>"
        inv_html += _table([L["table"], "Role", "Columns", "Measures", "Data sources"],
                           [[t["name"], str(t["role"]), str(len(t["columns"])), str(len(t["measures"])),
                             ", ".join(t["data_sources"])] for t in m["tables"]])
    if ins["sources"]:
        inv_html = f"<h3>{e(L['sources'])}</h3>" + _table(["Connector", L["table"]], [[k, ", ".join(v)] for k, v in
                                                                                     ins["sources"].items()]) + inv_html
    parts.append(_section("inventory", L["inventory"], inv_html or f'<p class="muted">{e(L["none"])}</p>'))

    nav_ids = ["overview", "summary", "priorities", "rules", "findings", "relationships", "dax", "visuals", "performance",
               "impact", "hypotheses", "actions", "limitations", "inventory"]
    nav_label = {**{i: L[i] for i in nav_ids}, "relationships": L["model_map"], "dax": L["measures_t"],
                 "visuals": L["pages_t"]}
    nav = "".join(f'<a href="#{i}">{e(nav_label[i])}</a>' for i in nav_ids if f'id="{i}"' in "".join(parts))
    meta = [f"v{doc.get('version', '')}", f"{L['generated']}: {doc.get('generated_at') or '-'}", L["readonly"]]
    if scope.get("modules"):
        meta.append(", ".join(scope["modules"]))
    if scope.get("performance_log"):
        meta.append(f"log: {scope['performance_log']}")
    head = (f'<header class="top"><div class="row">{_LOGO}<div><h1>Power BI PBIP Forensics</h1>'
            f'<div class="sub">{e(L["title"])} · <b>{e(doc.get("project"))}</b></div></div></div>'
            f'<div class="meta">' + "".join(f"<span>{e(m)}</span>" for m in meta) + "</div></header>")
    return (f'<!doctype html><html lang="{e(lang)}"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width, initial-scale=1"><title>PBIP Forensics · {e(doc.get("project"))}</title>'
            f"<style>{_CSS}</style></head><body>{head}<nav class='tabs'>{nav}</nav><main>{''.join(parts)}</main>"
            f"<footer>{e(L['footer'])}</footer><script>{_JS}</script></body></html>")


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
    if sev:  # notas, resumo em linguagem simples e ações rápidas (somente auditoria completa)
        ins = compute_insights(doc, lang)
        il = INS_LABELS.get(lang, INS_LABELS["en"])
        sc = ins["scores"]
        pt = lang == "pt-BR"
        areas = [f"{il[a['key']]}: {'–' if a['score'] is None else a['score']} ({il[a['grade']]})"
                 for a in sc["areas"]]
        b.append(("p", f"**{'Nota de saúde' if pt else 'Health score'}: {sc['overall']}/100 "
                       f"({il[sc['grade']]})** · " + " · ".join(areas) + f". _{sc['formula']}_"))
        b.append(("h3", "Em palavras simples" if pt else "In plain words"))
        b.append(("ul", ins["narrative"]))
        b.append(("h3", "O que fazer primeiro" if pt else "What to do first"))
        b.append(("ol", [f"**{w['title']}** — {il[w['effort']]}, {w['severity']}, {w['count']}× (`{w['rule_id']}`): "
                         f"{w['recommendation']}" for w in ins["quick_wins"]]))
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


def render(doc: dict[str, Any], fmt: str, lang: str = "en") -> str:
    if fmt == "json":
        return json.dumps(doc, indent=2, ensure_ascii=False)
    blocks = build_blocks(doc, lang)
    if fmt == "markdown":
        return to_markdown(blocks)
    if fmt == "html":
        return to_html_report(doc, lang)
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
