<p align="center">
  <img src="docs/assets/logo-512.png" alt="Power BI PBIP Forensics logo" width="260">
</p>

<h1 align="center">Power BI PBIP Forensics</h1>

<p align="center">
  <strong>Evidence-based, read-only forensics for Power BI projects<br>(PBIP · PBIR · TMDL · DAX · Performance Analyzer)</strong>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.0.0-blue">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776AB">
  <img alt="Tests" src="https://img.shields.io/badge/tests-93%20passing-brightgreen">
  <img alt="Coverage" src="https://img.shields.io/badge/coverage-87%25-green">
  <img alt="Dependencies" src="https://img.shields.io/badge/runtime%20deps-none-success">
  <img alt="License" src="https://img.shields.io/badge/license-proprietary-lightgrey">
</p>

<p align="center">
  <a href="#overview">Overview</a> ·
  <a href="#features">Features</a> ·
  <a href="#local-installation">Install</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="#security-and-privacy">Security</a> ·
  <a href="#packaging-for-agensi">Agensi skill</a>
</p>

Created by **Vinicius de Souza Santos** · [github.com/ViniciusKanh](https://github.com/ViniciusKanh) · Proprietary (see [Licensing](#licensing)).

---

## Overview

Power BI PBIP Forensics has two parts:

1. **Forensics Engine**: a Python 3.11+ package and CLI (`pbip-forensics`). It parses Power BI Project files,
   builds the relationship and dependency graphs, and produces findings with verifiable evidence.
2. **Agent Skill**: a package for the Agensi marketplace (`SKILL.md`, standalone scripts, references and
   templates). It guides AI agents (Claude Code, Codex and others) through real diagnoses on local files.

Everything runs locally and offline, uses only the Python standard library, and never modifies the analyzed project.

## The problem it solves

Diagnosing Power BI behaviour usually means clicking through Model view, the DAX editor and every visual by hand.
Typical questions include:

- *Why is this table showing unrelated customers?*
- *Why does this measure ignore my slicer?*
- *Why is the total different from the visible rows?*
- *Which visuals make the page slow?*
- *What will this change break?*

PBIP stores the report and the model as text, so these questions can be answered from the files, with evidence,
before anyone opens Power BI Desktop.

## What makes it different

- **Evidence first.** Every finding has a stable ID, a source path, a line number when available, evidence lines,
  an explanation, impact, a recommendation and a verification procedure.
- **Honest statuses.** Each finding is `confirmed` (proven by structure), `potential` (a rule-based risk) or
  `inconclusive` (not interpretable). Confidence is qualitative, never an invented percentage.
- **Real parsing.** It includes an indentation-aware TMDL parser and a DAX tokenizer with a call tree; it is not
  regex guessing. PBIR fields follow the published JSON schemas.
- **Graph algorithms.** Direction-aware filter-propagation paths, blocked-path explanations, a cycle basis
  that separates ambiguous loops from harmless ones, and Tarjan SCC for measure cycles.
- **Question-driven investigation.** Ranked root-cause hypotheses for filter-propagation problems.
- **Agent-safe by design.** Read-only, scope-restricted and secret-aware. Project content is treated as
  untrusted data.

## Architecture

```text
src/pbip_forensics/
  security/    scope, symlinks, sensitive files, size limits, redaction
  discovery/   project detection (.pbip, *.Report, *.SemanticModel, .pbix flagged)
  parsers/     tmdl.py · model_loader.py (TMDL/TMSL) · pbir.py (PBIR/PBIR-Legacy) · dax.py (tokenizer)
  graph/       relationship graph, paths, cycles, SCC
  analyzers/   semantic index · model/DAX/visual rules · filters (investigate) · performance · diff · stages
  findings/    catalog of rules · issue findings · summary (dedupe/sort)
  reporting/   Markdown / HTML / JSON rendering · merge of skill outputs
  entrypoints/ sources of the standalone skill scripts
  cli.py
agensi/powerbi-pbip-forensics/   SKILL.md · scripts/ (generated) · references/ · templates/
tools/        build_skill.py · package_agensi.py · make_fixtures.py · run_demo.py · gen_docs.py · script_metrics.py
tests/        unit/ · integration/ · fixtures/ (synthetic)
examples/     synthetic_project/ · synthetic_project_v2/ · sample_performance/ · sample_reports/
docs/         architecture · supported-formats · diagnostic-rules · limitations · validation-results · agensi-*
```

See [docs/architecture.md](docs/architecture.md).

## Features

| Module | What it does |
|---|---|
| Project Discovery | Detects `.pbip`, `*.Report` (`definition.pbir`), `*.SemanticModel` (`definition.pbism`), PBIR, PBIR-Legacy (limited), TMDL, `model.bim`. Inventories reports, pages, visuals, tables, columns, measures, relationships, connector names, filters and dependencies. |
| Semantic Model Inspector | Inactive, bidirectional, many-to-many and one-to-one relationships; ambiguous propagation paths; harmless loops; disconnected tables; broken relationship references; key type mismatch; table roles (fact/dimension/bridge); auto date tables. |
| DAX Static Analyzer | Reference resolution and dependency graph; missing references; circular dependencies; FILTER over tables in CALCULATE; nested iterators; context transition over fact tables; ALL/REMOVEFILTERS/ALLSELECTED/CROSSFILTER/USERELATIONSHIP checks; totals that differ from row sums; `/` vs DIVIDE; IFERROR. |
| Visual Dependency Inspector | Page → Visual → Field/Measure → Table map; invalid bindings; custom or uninterpretable visuals recorded as limitations; visuals that use complex measures. |
| Filter & Relationship Diagnostics | `investigate` command: active and blocked paths hop by hop, inactive or one-way hops, measure filter modifiers, visual filters, and ranked hypotheses with verification steps. |
| Performance Analyzer (preview) | Reads exported JSON (validated with synthetic exports only; real-export compatibility pending). Per-visual DAX query / Direct query / Visual display / Other, ranked bottlenecks, investigation actions. Uses measured values only. |
| Change Impact | Diff of tables, columns, measures (token-level; formatting-only changes are separated), relationships, pages and visuals, with dependent measures and affected visuals. |
| Reports | Markdown, static HTML (no JavaScript) and JSON with all required sections; English or Brazilian Portuguese headings. |

## Supported formats

PBIP (pbipProperties 1.0.0), PBIR definitionProperties 2.0.0 and PBIR `definition/` (visualContainer 2.x,
visualConfiguration 2.x, semanticQuery 1.x, page 2.0.0, filterConfiguration 1.2.0), TMDL, TMSL `model.bim`,
and Performance Analyzer exports. PBIR-Legacy support is limited and PBIX is not supported. Details are in
[docs/supported-formats.md](docs/supported-formats.md).

## Local installation

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"      # the engine itself has no runtime dependencies
pbip-forensics --version
```

Without installing, you can run `PYTHONPATH=src python -m pbip_forensics ...` (on Windows PowerShell:
`$env:PYTHONPATH="src"`).

## Usage

```bash
pbip-forensics scan --project ./examples/synthetic_project
pbip-forensics audit --project ./examples/synthetic_project --output ./reports
pbip-forensics audit --project ./examples/synthetic_project --performance ./examples/sample_performance/performance.json --output ./reports --lang pt-BR
pbip-forensics performance --input ./examples/sample_performance/performance.json
pbip-forensics diff --before ./examples/synthetic_project --after ./examples/synthetic_project_v2
pbip-forensics investigate --project ./examples/synthetic_project --from-table Customer --to-table Account --visual "Customer Accounts"
pbip-forensics report --input ./reports/findings.json --format markdown
```

Common options: `--format json|markdown|html|all`, `--output DIR` (must be outside the project),
`--lang en|pt-BR`, `--max-file-mb N`, `--fail-on SEVERITY` (audit; useful in CI) and `--debug`.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Findings at or above `--fail-on` |
| 2 | Invalid input |
| 3 | Limit exceeded |
| 4 | Refused by the security policy |
| 5 | Invalid performance log |
| 10 | Internal error |

## Audit workflow

1. `scan`: confirm what was detected and check `parse_issues`.
2. `audit` (optionally with `--performance`): read the Executive Summary, then confirmed HIGH/CRITICAL findings.
3. `investigate`: run it for each functional question (filter source → target table or measure).
4. `diff`: run it before publishing a new version. Regression-test the visuals it lists.
5. Verify in Power BI Desktop using each finding's `verification` field.

## Understanding the diagnostics

The full list is in [docs/diagnostic-rules.md](docs/diagnostic-rules.md).

| Severity | Use |
|---|---|
| CRITICAL | Model cannot work as defined |
| HIGH | Broken or very likely wrong behaviour |
| MEDIUM | Significant risk |
| LOW | Minor risk |
| INFO | Context |

| Status | Meaning |
|---|---|
| confirmed | Proven by file structure, or measured in a log |
| potential | Rule-based risk that needs verification |
| inconclusive | Could not be interpreted |

Investigation confidence:

| Confidence | Basis |
|---|---|
| high | Direct structural evidence |
| medium | The structure allows it; intent or data decides |
| low | No structural blocker found; data or interactions are suspected |

## Example reports

Real outputs, generated by `python tools/run_demo.py` from the synthetic project, are in
[`examples/sample_reports/`](examples/sample_reports/):

- `cli_audit/`: Markdown, HTML and JSON, with a performance log.
- `cli_audit_pt-BR/`
- `cli_investigation/`
- `cli_diff/`
- `skill_outputs/`: JSON from each standalone script.
- `skill_combined_report/`: merged report.

## Tests

```bash
python tools/make_fixtures.py        # regenerate synthetic fixtures (optional)
python -m pytest --cov=pbip_forensics
ruff check src tests tools && mypy
```

The tests cover 20+ scenarios, including negative ones that guard against false positives. They also run
every bundled script alone, in an isolated temporary folder, and compare its output with the engine.
Measured results are in [docs/validation-results.md](docs/validation-results.md).

## Known limitations

Static analysis only (no DAX execution, no data). PBIX and calculation-group semantics are out of scope.
PBIR-Legacy support is best-effort. The Performance Analyzer JSON layout is not documented on Microsoft
Learn; validate it with a real export. Agensi scripts are larger than the recommended 20 KB. See
[docs/limitations.md](docs/limitations.md).

## Documentation

| Document | Content |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Modules, data flow, determinism, skill bundling |
| [docs/supported-formats.md](docs/supported-formats.md) | Formats, schema versions, fields used, limits |
| [docs/diagnostic-rules.md](docs/diagnostic-rules.md) | Every rule: severity, status, false-positive safeguards |
| [docs/limitations.md](docs/limitations.md) | Known limitations |
| [docs/validation-results.md](docs/validation-results.md) | Measured test, coverage, timing and parity results |
| [docs/agensi-listing.md](docs/agensi-listing.md) | Marketplace listing text |
| [docs/agensi-compliance.md](docs/agensi-compliance.md) | Agensi packaging compliance report |
| [docs/PUBLISH_AGENSI.md](docs/PUBLISH_AGENSI.md) | Publishing and post-publication test checklist |
| [docs/licensing-options.md](docs/licensing-options.md) | Licensing alternatives (decision pending) |
| [agensi/powerbi-pbip-forensics/SKILL.md](agensi/powerbi-pbip-forensics/SKILL.md) | Agent skill instructions |

## Security and privacy

- **Read-only.** The project is never modified. Output must be written outside the project folder.
- **Scope.** Only the given folder is read. Symlinks pointing outside are not followed, and `byPath` targets
  outside the scope are rejected.
- **Secrets.** `.env*`, keys, certificates, `credentials*`/`secrets*`, `.pbi/localSettings.json` and
  `cache.abf` are never read.
- **Connection data.** Only M connector names are kept (for example `Sql.Database`), never arguments.
  `byConnection` strings are never copied. Redaction helpers mask passwords, tokens and signed URLs.
- **No execution.** DAX, M and JSON are parsed as data. Nothing is evaluated.
- **No network.** The skill scripts are scanned at build time for network, subprocess, dynamic execution,
  deletion and encoding patterns.
- **Untrusted content.** Project text, including measure names and descriptions, is treated as data. HTML
  output is escaped.

## Agent compatibility

The skill uses plain Python scripts and Markdown instructions, so any agent that can run local Python can
use it. It was designed for Claude Code and Codex-style agents. Compatibility was verified by running the
scripts as isolated temporary files (`python -I`). It was **not** tested inside each third-party agent
product.

## Packaging for Agensi

```bash
python tools/build_skill.py      # regenerate standalone scripts from the engine
python tools/gen_docs.py         # regenerate rule docs and references
python tools/package_agensi.py   # build and validate dist/powerbi-pbip-forensics-v1.0.0.zip
```

The ZIP contains a single `SKILL.md`, scripts, references and templates. The validation report is written to
`dist/validation-report.json`. See [docs/agensi-compliance.md](docs/agensi-compliance.md).

## Licensing

No license has been granted yet. The project is proprietary and private ("All rights reserved") until the
author decides. Options are in [docs/licensing-options.md](docs/licensing-options.md). Hosting the source on
GitHub does not grant any rights to use, copy or redistribute it.

## Changelog

### 1.0.0 (2026-11-08)

- First release: discovery, TMDL/TMSL/PBIR parsers, DAX tokenizer, relationship graph, MOD/DAX/VIS/PERF rules,
  filter investigation, Performance Analyzer reader, change impact, Markdown/HTML/JSON reports, CLI, Agensi
  skill with six standalone scripts, synthetic examples and tests.

## Credits

Designed and developed by **Vinicius de Souza Santos** ([ViniciusKanh](https://github.com/ViniciusKanh)).
Power BI, PBIP, PBIR, TMDL and DAX are Microsoft technologies. This product is not affiliated with or endorsed
by Microsoft.
#   p o w e r b i - p b i p - f o r e n s i c s  
 