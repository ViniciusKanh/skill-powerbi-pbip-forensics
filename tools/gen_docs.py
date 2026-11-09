"""Gera a documentação de regras a partir do catálogo e copia referências para a skill.

Execução: python tools/gen_docs.py
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pbip_forensics.findings.catalog import RULES  # noqa: E402

HEADER = """# Diagnostic rules

All rules are static. They read only metadata and never execute DAX or read data values.
Statuses: **confirmed**, proven by file structure or by a measured log value;
**potential**, a risk identified by a rule that needs verification;
**inconclusive**, an item that could not be interpreted.
Severities: CRITICAL, HIGH, MEDIUM, LOW, INFO. Confidence is never expressed as a percentage.

| Rule | Category | Severity | Status | Detects | False-positive safeguard |
|---|---|---|---|---|---|
"""


def main() -> None:
    rows = "".join(f"| {rid} | {cat} | {sev} | {st} | {what} | {guard} |\n"
                   for rid, (cat, sev, st, what, guard) in RULES.items())
    text = HEADER + rows
    (ROOT / "docs" / "diagnostic-rules.md").write_text(text, encoding="utf-8")
    refs = ROOT / "agensi" / "powerbi-pbip-forensics" / "references"
    refs.mkdir(parents=True, exist_ok=True)
    (refs / "diagnostic-rules.md").write_text(text, encoding="utf-8")
    shutil.copyfile(ROOT / "docs" / "supported-formats.md", refs / "supported-formats.md")
    shutil.copyfile(ROOT / "docs" / "limitations.md", refs / "limitations.md")
    print("docs generated")


if __name__ == "__main__":
    main()
