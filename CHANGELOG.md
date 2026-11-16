# Changelog

## Unreleased — Python CLI packaging (development branch `feat/pbip-forensics-python-cli`)
- Prepared `powerbi-pbip-forensics` 1.0.0 for professional, installable Python distribution. The
  engine, rules, parsers, CLI and Agensi skill are unchanged; this work is packaging-only.
- `pyproject.toml`: modernized metadata (SPDX `license` expression + `license-files`, `project.urls`,
  extra classifiers, `py.typed`), added `build`/`twine`/`setuptools`/`wheel` to the `dev` extra, kept
  the `Private :: Do Not Upload` safety classifier.
- Added `tests/packaging/test_distribution.py` (11 tests): builds the real wheel and sdist and
  installs each in an isolated, throwaway virtual environment to verify the CLI works with no
  `PYTHONPATH` and no repository path on `sys.path`, that reports generate correctly, that exit
  codes are correct, and that no secrets or unexpected files are packaged. Full suite: 112 tests
  passing (Python 3.11, 3.12, 3.13).
- Added `.github/workflows/python-package-ci.yml`: lint (ruff) + type-check (mypy) + tests + build +
  `twine check` + install smoke-test, on pushes to `feat/pbip-forensics-python-cli` only. No
  `pull_request` trigger, no publishing step, no PyPI credentials, minimal `permissions: contents:
  read`.
- Added `docs/python-packaging.md`: build instructions and the full (not executed) procedure for a
  future TestPyPI/PyPI publication, including a Trusted-Publishing workflow skeleton gated on an
  explicit, author-created release tag.
- Verified: the name `powerbi-pbip-forensics` is available on PyPI (checked 2026-11); TestPyPI
  availability could not be checked from this environment (network restriction) and should be
  confirmed manually before the first TestPyPI upload.
- `2026-11-16`: at the author's explicit request, removed the `Private :: Do Not Upload` safety
  classifier from `pyproject.toml` to allow the first real PyPI upload of 1.0.0. The upload itself
  was run by the author locally (`twine upload`) with their own PyPI API token, never shared in
  this session — see docs/python-packaging.md.
- **Published on PyPI on 2026-11-16**: https://pypi.org/project/powerbi-pbip-forensics/1.0.0/ —
  `pip install powerbi-pbip-forensics` now works for anyone. No GitHub push, PR or tag was made as
  part of this; `main` was not touched.

## 1.0.0 — 2026-11-08
- First release. Includes:
  - Discovery of PBIP projects.
  - Parsers for TMDL, TMSL, PBIR and PBIR-Legacy (limited support).
  - DAX tokenizer and relationship graph.
  - Diagnostic rules for the model (MOD), DAX, visuals (VIS) and performance (PERF).
  - Filter-propagation investigation.
  - Performance Analyzer reader (preview).
  - Change-impact analysis between project versions.
  - Markdown, HTML and JSON reports.
  - Command-line interface.
  - Agensi skill with six standalone scripts.
  - Synthetic examples and 101 tests.
  - Insight layer: health score per area (indicative formula shown in the report), plain-language summary,
    grouped "what to do first" actions, model map diagram, measure complexity/hub statistics, page cards and
    data-source list (HTML and Markdown, English and pt-BR).
  - Rules MOD010 (visible foreign keys), DAX014 (measures without format), VIS008 (heavy pages) and COL001
    (unused columns); fields used in conditional formatting count as used.
  - Fewer false positives in VIS005/VIS006/VIS007 (lookup and parameter tables, measures linking tables,
    formatting-only page references) and DAX008 lowered to INFO.
