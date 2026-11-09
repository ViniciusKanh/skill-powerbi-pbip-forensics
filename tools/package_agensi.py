"""Empacota e valida o ZIP comercial da skill para a Agensi.

1. Gera dist/powerbi-pbip-forensics-v1.0.0.zip a partir de agensi/powerbi-pbip-forensics/.
2. Reabre o ZIP e valida: SKILL.md único com frontmatter, limites, tipos de arquivo,
   ausência de binários/caches/segredos e padrões proibidos.
3. Extrai cada script para um arquivo temporário isolado e o executa com `python -I`
   sobre o projeto sintético (simulação do comprador).
4. Grava dist/validation-report.json com os resultados observados.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "agensi" / "powerbi-pbip-forensics"
DIST = ROOT / "dist"
ZIP = DIST / "powerbi-pbip-forensics-v1.0.0.zip"
TEXT_EXT = {".md", ".py", ".txt", ".json"}
BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".wasm", ".jar", ".pyc", ".pyd", ".bin", ".zip", ".abf", ".pbix"}
SECRET_RE = re.compile(r"(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]"
                       r"|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{20,}")
sys.path.insert(0, str(ROOT / "tools"))
from build_skill import FORBIDDEN  # noqa: E402


def frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        raise SystemExit("SKILL.md must start with YAML frontmatter")
    block = text[4:text.index("\n---", 4)]
    out = {}
    for line in block.splitlines():
        m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip('"')
    return out


def build() -> list[str]:
    DIST.mkdir(exist_ok=True)
    if ZIP.exists():
        ZIP.unlink()
    files = sorted(p for p in SKILL.rglob("*") if p.is_file() and "__pycache__" not in p.parts
                   and not p.name.startswith("."))
    with zipfile.ZipFile(ZIP, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in files:
            arc = "powerbi-pbip-forensics/" + p.relative_to(SKILL).as_posix()
            info = zipfile.ZipInfo(arc, date_time=(2026, 11, 8, 0, 0, 0))  # reprodutível
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, p.read_bytes())
    return [p.relative_to(SKILL).as_posix() for p in files]


def validate() -> dict:
    checks: dict[str, object] = {}
    with zipfile.ZipFile(ZIP) as zf:
        names = zf.namelist()
        assert zf.testzip() is None, "corrupted zip"
        skill_mds = [n for n in names if n.endswith("SKILL.md")]
        checks["skill_md_count"] = len(skill_mds)
        fm = frontmatter(zf.read(skill_mds[0]).decode("utf-8"))
        checks["frontmatter"] = {k: fm.get(k) for k in ("name", "description", "version")}
        checks["frontmatter_ok"] = bool(fm.get("name") and fm.get("description") and fm.get("version") == "1.0.0")
        checks["file_count"] = len(names)
        checks["other_text_files"] = len(names) - len(skill_mds)
        total_chars = 0
        problems = []
        for n in names:
            data = zf.read(n)
            ext = Path(n).suffix.lower()
            if ext in BINARY_EXT or ext not in TEXT_EXT:
                problems.append(f"non-text or binary file: {n}")
            if any(part in n for part in ("__pycache__", ".git/", "node_modules", ".venv", "site-packages")):
                problems.append(f"forbidden folder: {n}")
            if Path(n).name.startswith(".env") and not n.endswith(".env.example"):
                problems.append(f"env file: {n}")
            text = data.decode("utf-8")
            total_chars += len(text)
            if SECRET_RE.search(text):
                problems.append(f"possible secret: {n}")
            if n.endswith(".py"):
                for pat, why in FORBIDDEN.items():
                    if re.search(pat, text):
                        problems.append(f"forbidden pattern ({why}) in {n}")
        checks["total_characters"] = total_chars
        checks["problems"] = problems
    checks["zip_bytes"] = ZIP.stat().st_size
    checks["sha256"] = hashlib.sha256(ZIP.read_bytes()).hexdigest()
    checks["limits_ok"] = (checks["zip_bytes"] < 50 * 1024 * 1024 and checks["file_count"] <= 1000
                           and checks["other_text_files"] <= 200 and total_chars <= 6_000_000)
    return checks


def run_scripts() -> list[dict]:
    """Executa cada script do ZIP como arquivo temporário isolado."""
    proj = ROOT / "examples" / "synthetic_project"
    v2 = ROOT / "examples" / "synthetic_project_v2"
    log = ROOT / "examples" / "sample_performance" / "performance.json"
    plans = {
        "pbip_inspect.py": ["--project", str(proj)],
        "pbip_model_audit.py": ["--project", str(proj)],
        "pbip_visual_deps.py": ["--project", str(proj), "--from-table", "Customer", "--to-table", "Account"],
        "pbip_perf_log.py": ["--input", str(log)],
        "pbip_diff.py": ["--before", str(proj), "--after", str(v2)],
    }
    results = []
    with zipfile.ZipFile(ZIP) as zf, tempfile.TemporaryDirectory() as tmp:
        outdir = Path(tmp) / "out"
        for script, args in plans.items():
            code = zf.read(f"powerbi-pbip-forensics/scripts/{script}")
            with tempfile.NamedTemporaryFile("wb", suffix=".py", dir=tmp, delete=False) as fh:
                fh.write(code)
                temp_script = fh.name
            t0 = time.perf_counter()
            proc = subprocess.run([sys.executable, "-I", temp_script, *args, "--output", str(outdir)],
                                  capture_output=True, text=True, cwd=tmp, timeout=300)
            Path(temp_script).unlink()
            results.append({"script": script, "exit_code": proc.returncode, "seconds": round(time.perf_counter() - t0, 3),
                            "stderr": proc.stderr.strip()[-300:]})
        code = zf.read("powerbi-pbip-forensics/scripts/pbip_report.py")
        rep = Path(tmp) / "tmp_report.py"
        rep.write_bytes(code)
        proc = subprocess.run([sys.executable, "-I", str(rep), "--input", *map(str, sorted(outdir.glob("*.json"))),
                               "--output", str(Path(tmp) / "final")], capture_output=True, text=True, cwd=tmp)
        md = (Path(tmp) / "final" / "audit-report.md")
        results.append({"script": "pbip_report.py", "exit_code": proc.returncode,
                        "report_sections_ok": md.is_file() and "## Evidence Appendix" in md.read_text(encoding="utf-8")})
    return results


def main() -> int:
    files = build()
    checks = validate()
    runs = run_scripts()
    sizes = {p.name: p.stat().st_size for p in sorted((SKILL / "scripts").glob("*.py"))}
    report = {"zip": ZIP.relative_to(ROOT).as_posix(), "files": files, "checks": checks, "script_bytes": sizes,
              "script_runs": runs, "python": sys.version.split()[0]}
    (DIST / "validation-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    ok = (checks["skill_md_count"] == 1 and checks["frontmatter_ok"] and checks["limits_ok"]
          and not checks["problems"] and all(r["exit_code"] == 0 for r in runs))
    print(json.dumps({"ok": ok, "zip_bytes": checks["zip_bytes"], "files": checks["file_count"],
                      "problems": checks["problems"], "runs": [(r["script"], r["exit_code"]) for r in runs]}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
