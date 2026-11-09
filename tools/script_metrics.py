"""Mede o tamanho dos scripts da skill: bytes totais, bytes sem comentários e
"lógica" (código sem comentários, linhas em branco e literais de texto —
textos de mensagens/regras são dados embutidos, conforme a orientação da Agensi)."""

from __future__ import annotations

import io
import json
import sys
import tokenize
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "agensi" / "powerbi-pbip-forensics" / "scripts"


def measure(path: Path) -> dict[str, int]:
    src = path.read_text(encoding="utf-8")
    no_comments, logic = [], []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
                        tokenize.ENCODING, tokenize.ENDMARKER):
            continue
        no_comments.append(tok.string)
        is_text = tok.type == tokenize.STRING or tok.type in (
            getattr(tokenize, "FSTRING_MIDDLE", -1),)
        logic.append('""' if is_text else tok.string)
    return {"bytes_total": len(src.encode("utf-8")),
            "bytes_code_tokens": len(" ".join(no_comments).encode("utf-8")),
            "bytes_logic_without_text_literals": len(" ".join(logic).encode("utf-8"))}


if __name__ == "__main__":
    res = {p.name: measure(p) for p in sorted(SCRIPTS.glob("*.py"))}
    json.dump(res, sys.stdout, indent=2)
    print()
