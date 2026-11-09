"""Configuração compartilhada dos testes."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pbip_forensics.analyzers.audit import run_audit  # noqa: E402
from pbip_forensics.discovery.detector import discover  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
EXAMPLES = ROOT / "examples"


def audit(path: Path, perf: dict[str, Any] | None = None) -> dict[str, Any]:
    return run_audit(discover(path), perf, "perf.json" if perf else "")


def rules(doc: dict[str, Any], rule_id: str, status: str | None = None) -> list[dict[str, Any]]:
    return [f for f in doc["findings"] if f["rule_id"] == rule_id and (status is None or f["status"] == status)]


@pytest.fixture(scope="session")
def synthetic_doc() -> dict[str, Any]:
    return audit(EXAMPLES / "synthetic_project")
