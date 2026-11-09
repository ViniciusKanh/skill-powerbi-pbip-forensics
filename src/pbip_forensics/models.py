"""Modelos de dados centrais do Power BI PBIP Forensics.

Todas as estruturas são dataclasses simples e serializáveis em JSON, para que
os resultados do motor possam ser comparados com os scripts independentes da
skill (testes de paridade).
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

TOOL_NAME = "powerbi-pbip-forensics"
TOOL_VERSION = "1.0.0"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
STATUSES = ("confirmed", "potential", "inconclusive")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES)}


class ForensicsError(Exception):
    """Erro controlado do motor (mensagem segura para exibição ao usuário)."""

    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass
class ParseIssue:
    """Problema de leitura/parsing registrado sem interromper a auditoria."""

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
        """Rótulo legível e estável do relacionamento."""
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
    """Achado de auditoria com evidência verificável e ID estável."""

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
    """Gera um ID determinístico (independe de ordem de execução ou horário)."""
    digest = hashlib.sha1(f"{rule_id}|{path}|{object_ref}".encode(), usedforsecurity=False)
    return f"{rule_id}-{digest.hexdigest()[:8]}"


def to_jsonable(obj: Any) -> Any:
    """Converte dataclasses (inclusive aninhadas) em estruturas JSON."""
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, list):
        return [to_jsonable(o) for o in obj]
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    return obj


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Ordena por severidade, status e ID para saída determinística."""
    status_rank = {s: i for i, s in enumerate(STATUSES)}
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], status_rank[f.status], f.id))
