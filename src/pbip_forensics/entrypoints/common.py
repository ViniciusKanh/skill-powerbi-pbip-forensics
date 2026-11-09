"""Utilitários compartilhados pelos scripts independentes da skill.

Os scripts são somente leitura em relação ao projeto: gravam apenas no
diretório de saída informado, que precisa estar fora do projeto auditado.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pbip_forensics.models import TOOL_NAME, TOOL_VERSION, ForensicsError
from pbip_forensics.security.safety import prepare_output_dir


def skill_parser(description: str) -> argparse.ArgumentParser:
    """Parser com opções comuns (--output, --max-file-mb)."""
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--output", help="output directory (outside the audited project); default: print JSON")
    p.add_argument("--max-file-mb", type=float, default=25.0, help="per-file size limit in MB")
    return p


def skill_header(script: str, project: str | None) -> dict[str, Any]:
    return {"tool": TOOL_NAME, "version": TOOL_VERSION, "script": script, "project": project,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds")}


def skill_emit(doc: dict[str, Any], output: str | None, filename: str, roots: list[Path]) -> None:
    """Grava o JSON no diretório autorizado ou imprime em stdout."""
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
    """Executa com mensagens de erro seguras e códigos de saída documentados."""
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
