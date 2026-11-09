"""Testes da camada de segurança: escopo, segredos, limites e redação."""

import os
from pathlib import Path

import pytest

from pbip_forensics.discovery.detector import discover
from pbip_forensics.models import ForensicsError
from pbip_forensics.security.safety import prepare_output_dir, read_text, redact, resolve_root, safe_walk
from tests.conftest import FIXTURES, audit


def test_redaction_patterns():
    text = 'Password=abc;User ID=me; Authorization="Bearer XYZ.123" https://u:p@host/x?sig=ABCDEFGHIJKLMNOPQRST'
    out = redact(text)
    for secret in ("abc", "XYZ.123", "u:p@", "ABCDEFGHIJKLMNOPQRST"):
        assert secret not in out


def test_sensitive_files_are_never_read():
    root = resolve_root(FIXTURES / "security_cases")
    files, skipped = safe_walk(root)
    names = {f.name for f in files}
    assert ".env" not in names and "credentials.json" not in names and "localSettings.json" not in names
    assert any("sensitive-file-not-read" in s for s in skipped)
    with pytest.raises(ForensicsError):
        read_text(root, root / ".env")


def test_secrets_and_injection_text_not_leaked_as_instructions():
    doc = audit(FIXTURES / "security_cases")
    import json
    dumped = json.dumps(doc)
    assert "SHOULD_NEVER_BE_READ" not in dumped
    assert "SECRET_TOKEN_123456" not in dumped  # apenas o nome do conector é guardado
    assert "ABCDEFGHIJKLMNOPQRSTUV" not in dumped
    from pbip_forensics.reporting.render import render
    html_out = render(doc, "html")
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;" in html_out


def test_bypath_escape_is_blocked():
    project = discover(FIXTURES / "escape_bypath")
    rep = project.reports[0]
    assert rep.model_path is None
    assert any("not found inside the authorized scope" in i.message for i in rep.issues)


def test_read_outside_scope_refused(tmp_path: Path):
    inner = tmp_path / "inner"
    inner.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("x")
    with pytest.raises(ForensicsError):
        read_text(inner.resolve(), outside.resolve())


@pytest.mark.skipif(os.name == "nt", reason="symlink creation requires privileges on Windows")
def test_symlink_outside_scope_not_followed(tmp_path: Path):
    outside = tmp_path / "outside"
    (outside / "Leak.SemanticModel").mkdir(parents=True)
    (outside / "Leak.SemanticModel" / "definition.pbism").write_text('{"version": "4.0"}')
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "link").symlink_to(outside, target_is_directory=True)
    project = discover(proj)
    assert project.models == []
    assert any("symlink-outside-scope" in s for s in project.skipped)


def test_output_inside_project_refused(tmp_path: Path):
    root = resolve_root(FIXTURES / "simple_valid")
    with pytest.raises(ForensicsError) as exc:
        prepare_output_dir(root / "reports", [root])
    assert exc.value.exit_code == 4
    assert prepare_output_dir(tmp_path / "out", [root]).is_dir()


def test_large_file_limit(tmp_path: Path):
    big = tmp_path / "Big.SemanticModel" / "definition"
    big.mkdir(parents=True)
    (tmp_path / "Big.SemanticModel" / "definition.pbism").write_text('{"version": "4.0"}')
    (big / "t.tmdl").write_text("table T\n" + "\t/// x\n" * 50000)
    project = discover(tmp_path, max_bytes=1024)
    model = project.models[0]
    assert any("too large" in i.message for i in model.issues)
