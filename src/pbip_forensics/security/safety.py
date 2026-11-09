"""Camada de segurança: escopo autorizado, limites de tamanho e redação.

Regras aplicadas em toda leitura:
- somente arquivos dentro da raiz autorizada (após resolver links simbólicos);
- links simbólicos que apontam para fora da raiz são ignorados e registrados;
- arquivos sensíveis (.env, chaves, certificados) nunca são lidos;
- arquivos acima do limite configurado não são carregados;
- nada é executado: DAX, M e JSON são tratados apenas como texto/dados.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from pbip_forensics.models import ForensicsError

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
    """Remove segredos aparentes (senhas, tokens, chaves) de um texto."""
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE_RE.search(name))


def resolve_root(path: str | os.PathLike[str]) -> Path:
    """Valida e resolve o diretório raiz autorizado para a auditoria."""
    raw = Path(path).expanduser()
    if not raw.exists():
        raise ForensicsError(f"Path not found: {raw}", exit_code=2)
    if not raw.is_dir():
        raise ForensicsError(f"Not a directory: {raw}", exit_code=2)
    return raw.resolve()


def is_within(root: Path, candidate: Path) -> bool:
    """Retorna True se `candidate` (já resolvido) está dentro de `root`."""
    try:
        candidate.resolve().relative_to(root)
    except (ValueError, OSError):
        return False
    return True


def rel(root: Path, path: Path) -> str:
    """Caminho relativo com '/' (estável entre Windows e POSIX)."""
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.name


def safe_walk(root: Path, max_files: int = DEFAULT_MAX_FILES,
              exclude_dirs: set[str] | None = None) -> tuple[list[Path], list[str]]:
    """Percorre a raiz sem seguir links para fora do escopo.

    Retorna (arquivos permitidos, avisos de itens ignorados).
    """
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
    """Lê texto UTF-8 (com ou sem BOM) respeitando escopo e limite de tamanho."""
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
    """Lê JSON como dados (nunca executa conteúdo)."""
    return json.loads(read_text(root, path, max_bytes))


def prepare_output_dir(output: str | os.PathLike[str], forbidden_roots: list[Path]) -> Path:
    """Cria o diretório de saída, recusando locais dentro do projeto auditado.

    A auditoria é read-only: gravar relatórios dentro do projeto alteraria a
    árvore de arquivos analisada, por isso isso é bloqueado.
    """
    out = Path(output).expanduser().resolve()
    for root in forbidden_roots:
        if out == root or is_within(root, out):
            raise ForensicsError(
                "Output directory must be outside the audited project (read-only policy).", 4
            )
    out.mkdir(parents=True, exist_ok=True)
    return out
