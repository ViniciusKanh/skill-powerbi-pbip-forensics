"""Testes reais de empacotamento e instalação da distribuição Python.

Diferente dos demais testes (que importam ``pbip_forensics`` diretamente do
``src/`` via o ``sys.path`` ajustado em ``tests/conftest.py``), este módulo
constrói a wheel e o sdist com ``python -m build`` e instala cada um em um
ambiente virtual **isolado e temporário**, fora do repositório, para provar
que o pacote funciona exatamente como um usuário final o receberia: sem
``PYTHONPATH``, sem o diretório do repositório em ``sys.path`` e a partir de
qualquer diretório de trabalho.

Marcado com ``@pytest.mark.packaging``: são testes mais lentos (build real +
criação de venv), mas não dependem de rede (usam ``python -m build
--no-isolation``, reaproveitando o ``setuptools``/``wheel`` já instalados
como dependências de desenvolvimento — ver ``pyproject.toml``
``[project.optional-dependencies] dev``).
"""

from __future__ import annotations

import json
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest

from tests.conftest import EXAMPLES, ROOT

pytestmark = pytest.mark.packaging

SYNTHETIC_PROJECT = EXAMPLES / "synthetic_project"

# Padrões de texto que NUNCA devem aparecer num artefato distribuído.
_FORBIDDEN_PATTERNS = (
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "client_secret=",
)
_FORBIDDEN_FILENAMES = {".env", "credentials.json", "localsettings.json", "cache.abf"}


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=180, **kw)


@pytest.fixture(scope="session")
def built_distributions(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Builda wheel + sdist uma única vez para toda a sessão de testes."""
    out = tmp_path_factory.mktemp("dist")
    proc = _run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out)], cwd=ROOT)
    assert proc.returncode == 0, f"falha ao construir a distribuição:\n{proc.stdout}\n{proc.stderr}"
    wheels = list(out.glob("*.whl"))
    sdists = list(out.glob("*.tar.gz"))
    assert len(wheels) == 1, f"esperada 1 wheel, encontrei {wheels}"
    assert len(sdists) == 1, f"esperado 1 sdist, encontrei {sdists}"
    return {"wheel": wheels[0], "sdist": sdists[0]}


def _make_venv(path: Path) -> Path:
    """Cria um venv isolado (sem pacotes do repositório) e devolve o python dele."""
    venv.EnvBuilder(with_pip=True, clear=True).create(path)
    py = path / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    assert py.exists(), f"python do venv não encontrado em {py}"
    return py


@pytest.fixture(scope="session")
def wheel_venv_python(built_distributions: dict[str, Path], tmp_path_factory: pytest.TempPathFactory) -> Path:
    venv_dir = tmp_path_factory.mktemp("venv-wheel") / ".venv"
    py = _make_venv(venv_dir)
    proc = _run([str(py), "-m", "pip", "install", "--no-index", "--no-deps",
                 str(built_distributions["wheel"])])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return py


@pytest.fixture(scope="session")
def sdist_venv_python(built_distributions: dict[str, Path], tmp_path_factory: pytest.TempPathFactory) -> Path:
    venv_dir = tmp_path_factory.mktemp("venv-sdist") / ".venv"
    py = _make_venv(venv_dir)
    # O sdist precisa do build backend (setuptools/wheel) para ser instalado; usamos o índice normal
    # aqui (não --no-index) porque o ambiente de CI já tem acesso ao PyPI para resolver o build backend.
    proc = _run([str(py), "-m", "pip", "install", str(built_distributions["sdist"])])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return py


# ---------------------------------------------------------------------------
# Conteúdo dos artefatos: sem segredos, sem arquivos indevidos.
# ---------------------------------------------------------------------------

def test_wheel_contains_no_secrets_or_unexpected_files(built_distributions: dict[str, Path]):
    wheel = built_distributions["wheel"]
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
        assert names, "wheel vazia"
        for name in names:
            base = Path(name).name.lower()
            assert base not in _FORBIDDEN_FILENAMES, f"arquivo sensível empacotado: {name}"
        # Só o pacote pbip_forensics + metadados do dist-info devem estar presentes.
        unexpected = [n for n in names
                      if not n.startswith("pbip_forensics/") and "dist-info/" not in n]
        assert not unexpected, f"arquivos inesperados na wheel: {unexpected}"
        for name in names:
            if name.endswith((".py", ".txt", ".md")):
                text = zf.read(name).decode("utf-8", errors="replace")
                for pattern in _FORBIDDEN_PATTERNS:
                    assert pattern not in text, f"padrão sensível '{pattern}' encontrado em {name}"


def test_sdist_contains_no_env_or_credentials(built_distributions: dict[str, Path]):
    import tarfile
    with tarfile.open(built_distributions["sdist"]) as tf:
        names = tf.getnames()
        for name in names:
            base = Path(name).name.lower()
            assert base not in _FORBIDDEN_FILENAMES, f"arquivo sensível no sdist: {name}"
        assert not any(n.endswith(".git") or "/.git/" in n for n in names)


# ---------------------------------------------------------------------------
# Instalação real da wheel em venv isolado.
# ---------------------------------------------------------------------------

def test_wheel_installs_and_cli_on_path(wheel_venv_python: Path):
    bin_dir = wheel_venv_python.parent
    cli = bin_dir / ("pbip-forensics.exe" if sys.platform == "win32" else "pbip-forensics")
    assert cli.exists(), f"entry point não encontrado após instalar a wheel: {cli}"


def test_wheel_cli_help_from_other_directory(wheel_venv_python: Path, tmp_path: Path):
    cli = wheel_venv_python.parent / ("pbip-forensics.exe" if sys.platform == "win32" else "pbip-forensics")
    proc = _run([str(cli), "--help"], cwd=tmp_path)  # cwd fora do repositório
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "pbip-forensics" in proc.stdout
    assert "{run,scan,audit,performance,diff,investigate,report}" in proc.stdout


def test_wheel_module_entrypoint(wheel_venv_python: Path, tmp_path: Path):
    proc = _run([str(wheel_venv_python), "-m", "pbip_forensics", "--version"], cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1.0.0" in proc.stdout


def test_wheel_no_pythonpath_or_repo_on_syspath(wheel_venv_python: Path, tmp_path: Path):
    """A CLI deve funcionar sem PYTHONPATH e sem o diretório do repositório em sys.path."""
    import os
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = _run([str(wheel_venv_python), "-c", "import pbip_forensics; print(pbip_forensics.__file__)"],
                cwd=tmp_path, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    installed_path = Path(proc.stdout.strip())
    assert str(ROOT) not in str(installed_path), (
        "pbip_forensics está sendo importado do repositório-fonte, não do pacote instalado")
    assert "site-packages" in str(installed_path).replace("\\", "/")


def test_wheel_audit_on_synthetic_project(wheel_venv_python: Path, tmp_path: Path):
    out = tmp_path / "audit-out"
    cli = wheel_venv_python.parent / ("pbip-forensics.exe" if sys.platform == "win32" else "pbip-forensics")
    proc = _run([str(cli), "audit", "--project", str(SYNTHETIC_PROJECT), "--output", str(out),
                 "--format", "all", "--fail-on", "HIGH"], cwd=tmp_path)
    assert proc.returncode == 1, proc.stdout + proc.stderr  # há findings HIGH no projeto sintético
    produced = {p.name for p in out.iterdir()}
    assert produced == {"findings.json", "audit-report.md", "audit-report.html"}
    doc = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert doc["metrics"]["findings_total"] > 0
    assert (out / "audit-report.html").read_text(encoding="utf-8").strip().lower().startswith("<!doctype html>")


def test_wheel_audit_exit_code_success_when_no_high(wheel_venv_python: Path, tmp_path: Path):
    from tests.conftest import FIXTURES
    cli = wheel_venv_python.parent / ("pbip-forensics.exe" if sys.platform == "win32" else "pbip-forensics")
    proc = _run([str(cli), "audit", "--project", str(FIXTURES / "simple_valid"), "--output", str(tmp_path / "o2"),
                 "--fail-on", "HIGH"], cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_wheel_never_writes_inside_audited_project(wheel_venv_python: Path, tmp_path: Path):
    """A auditoria é read-only: nenhum arquivo do projeto sintético pode ser modificado."""
    before = {p: p.stat().st_mtime for p in SYNTHETIC_PROJECT.rglob("*") if p.is_file()}
    cli = wheel_venv_python.parent / ("pbip-forensics.exe" if sys.platform == "win32" else "pbip-forensics")
    _run([str(cli), "audit", "--project", str(SYNTHETIC_PROJECT), "--output", str(tmp_path / "o3")], cwd=tmp_path)
    after = {p: p.stat().st_mtime for p in SYNTHETIC_PROJECT.rglob("*") if p.is_file()}
    assert before == after


# ---------------------------------------------------------------------------
# Instalação real do sdist em venv isolado.
# ---------------------------------------------------------------------------

def test_sdist_installs_and_cli_works(sdist_venv_python: Path, tmp_path: Path):
    cli = sdist_venv_python.parent / ("pbip-forensics.exe" if sys.platform == "win32" else "pbip-forensics")
    assert cli.exists()
    proc = _run([str(cli), "--version"], cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "1.0.0" in proc.stdout


def test_sdist_audit_on_synthetic_project(sdist_venv_python: Path, tmp_path: Path):
    out = tmp_path / "audit-out-sdist"
    cli = sdist_venv_python.parent / ("pbip-forensics.exe" if sys.platform == "win32" else "pbip-forensics")
    proc = _run([str(cli), "audit", "--project", str(SYNTHETIC_PROJECT), "--output", str(out),
                 "--format", "json", "--fail-on", "HIGH"], cwd=tmp_path)
    assert proc.returncode == 1, proc.stdout + proc.stderr  # há findings HIGH no projeto sintético
    doc = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert doc["metrics"]["findings_total"] > 0
