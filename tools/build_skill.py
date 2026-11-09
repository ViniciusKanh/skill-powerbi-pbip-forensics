"""Gera os scripts independentes da skill Agensi a partir do motor modular.

Para cada script:
1. resolve transitivamente os imports `pbip_forensics.*` a partir do ponto de entrada;
2. ordena os módulos topologicamente (dependências primeiro);
3. remove imports internos e docstrings (os comentários `#` são preservados);
4. verifica colisões de nomes de nível superior entre módulos;
5. concatena com um cabeçalho e um bloco `if __name__ == "__main__"`;
6. valida a sintaxe e aplica uma varredura de padrões proibidos (rede, subprocessos,
   execução dinâmica, exclusão de arquivos, codificação ofuscada).

Assim, cada script empacotado funciona sozinho (a Agensi executa cada script como
arquivo temporário isolado) e mantém paridade com o motor por construção.
Execução: python tools/build_skill.py
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
PKG = "pbip_forensics"
OUT = ROOT / "agensi" / "powerbi-pbip-forensics" / "scripts"

SCRIPTS = {
    "pbip_full_audit.py": "pbip_forensics.entrypoints.ep_full_audit",
    "pbip_inspect.py": "pbip_forensics.entrypoints.ep_inspect",
    "pbip_model_audit.py": "pbip_forensics.entrypoints.ep_model_audit",
    "pbip_visual_deps.py": "pbip_forensics.entrypoints.ep_visual_deps",
    "pbip_perf_log.py": "pbip_forensics.entrypoints.ep_perf_log",
    "pbip_diff.py": "pbip_forensics.entrypoints.ep_diff",
    "pbip_report.py": "pbip_forensics.entrypoints.ep_report",
}

# Padrões que nunca devem existir nos scripts distribuídos.
FORBIDDEN = {
    r"\bimport\s+(subprocess|socket|ctypes|pickle|marshal|urllib|http|requests|ftplib|smtplib|telnetlib)\b": "network/process",
    r"\bfrom\s+(subprocess|socket|ctypes|urllib|http|requests)\b": "network/process",
    r"(?<![.\w])(eval|exec|compile|__import__)\s*\(": "dynamic code execution",
    r"\bos\.(system|popen|remove|unlink|rmdir|removedirs|exec\w*|spawn\w*)\b": "process/deletion",
    r"\bshutil\.(rmtree|move)\b": "deletion",
    r"\.unlink\(|\.rmdir\(": "deletion",
    r"\bbase64\b|\bcodecs\.decode\b|\bzlib\b": "encoded payloads",
    r"os\.environ": "environment harvesting",
}


def module_path(name: str) -> Path:
    rel = Path(*name.split("."))
    candidate = SRC / rel.with_suffix(".py")
    return candidate if candidate.is_file() else SRC / rel / "__init__.py"


def internal_imports(tree: ast.Module) -> list[str]:
    deps = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(PKG):
            deps.append(node.module)
        elif isinstance(node, ast.Import):
            deps.extend(a.name for a in node.names if a.name.startswith(PKG))
    return deps


def resolve(entry: str) -> list[str]:
    """Ordem topológica dos módulos necessários (DFS pós-ordem)."""
    order: list[str] = []
    state: dict[str, int] = {}

    def visit(mod: str) -> None:
        if state.get(mod) == 2:
            return
        if state.get(mod) == 1:
            raise SystemExit(f"import cycle at {mod}")
        state[mod] = 1
        tree = ast.parse(module_path(mod).read_text(encoding="utf-8"))
        for dep in internal_imports(tree):
            visit(dep)
        state[mod] = 2
        order.append(mod)

    visit(entry)
    return order


def strip_module(source: str) -> tuple[str, list[str], set[str]]:
    """Remove imports e docstrings; devolve (corpo, imports externos, nomes de topo)."""
    tree = ast.parse(source)
    lines = source.split("\n")
    remove: list[tuple[int, int, str | None]] = []  # (início, fim, substituto)
    external: list[str] = []
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                pass
            elif not internal_imports(ast.Module(body=[node], type_ignores=[])):
                external.append(ast.unparse(node))
            remove.append((node.lineno, node.end_lineno or node.lineno, None))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names.update(t.id for t in targets if isinstance(t, ast.Name))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and \
                    isinstance(first.value.value, str):
                repl = None
                if len(node.body) == 1:
                    indent = lines[first.lineno - 1][: len(lines[first.lineno - 1]) - len(lines[first.lineno - 1].lstrip())]
                    repl = indent + "pass"
                remove.append((first.lineno, first.end_lineno or first.lineno, repl))
    for start, end, repl in sorted(remove, reverse=True):
        lines[start - 1:end] = [repl] if repl is not None else []
    body = "\n".join(lines)
    body = re.sub(r"\n{3,}", "\n\n\n", body).strip("\n")
    return body, external, names


def merge_imports(imports: list[str], skip: set[str]) -> list[str]:
    """Agrupa imports externos por módulo (evita linhas duplicadas no bundle)."""
    plain: set[str] = set()
    froms: dict[str, set[str]] = {}
    for imp in imports:
        node = ast.parse(imp).body[0]
        if isinstance(node, ast.Import):
            plain.update(a.name if not a.asname else f"{a.name} as {a.asname}" for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            froms.setdefault(node.module, set()).update(
                a.name if not a.asname else f"{a.name} as {a.asname}" for a in node.names)
    lines = [f"import {n}" for n in sorted(plain - skip)]
    lines += [f"from {m} import {', '.join(sorted(n))}" for m, n in sorted(froms.items())]
    return lines


def build(script: str, entry: str) -> str:
    modules = resolve(entry)
    imports: list[str] = []
    seen_names: dict[str, str] = {}
    parts = []
    for mod in modules:
        body, ext, names = strip_module(module_path(mod).read_text(encoding="utf-8"))
        for n in names:
            if n in seen_names and n not in ("main",):
                raise SystemExit(f"{script}: name collision '{n}' in {mod} and {seen_names[n]}")
            seen_names[n] = mod
        for imp in ext:
            if imp not in imports:
                imports.append(imp)
        if body.strip():
            parts.append(f"# {'-' * 70}\n# módulo de origem: {mod}\n# {'-' * 70}\n{body}")
    header = f'''#!/usr/bin/env python3
"""Power BI PBIP Forensics — {script} (v1.0.0, Vinicius de Souza Santos).

Standalone, read-only script generated from the modular engine (src/{PKG}).
Requires only the Python 3.11+ standard library. Run with --help for usage.
Never modifies the analyzed project; writes only to --output (outside the project).
"""

# Arquivo gerado por tools/build_skill.py — não editar manualmente.
# Módulos incluídos: {", ".join(m.replace(PKG + ".", "") for m in modules)}

from __future__ import annotations

import sys

if sys.version_info < (3, 11):  # verificação antes de qualquer import dependente de versão
    sys.stderr.write("error: Python 3.11 or newer is required (found %d.%d)\\n" % sys.version_info[:2])
    raise SystemExit(2)

'''
    code = header + "\n".join(merge_imports(imports, skip={"sys"})) + "\n\n\n" + "\n\n\n".join(parts) + \
        '\n\n\nif __name__ == "__main__":\n    raise SystemExit(main())\n'
    compile(code, script, "exec")
    for pattern, reason in FORBIDDEN.items():
        if re.search(pattern, code):
            raise SystemExit(f"{script}: forbidden pattern ({reason}): {pattern}")
    return code


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for script, entry in SCRIPTS.items():
        code = build(script, entry)
        (OUT / script).write_text(code, encoding="utf-8", newline="\n")
        print(f"{script}: {len(code.encode('utf-8')):,} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
