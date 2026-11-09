# Architecture

## Overview

```text
                 ┌────────────── security/safety.py ──────────────┐
                 │ scope check · symlinks · secrets · size limits │
                 └────────────────────────┬───────────────────────┘
project folder ──► discovery/detector.py ──► parsers/ (tmdl · model_loader[TMSL] · pbir) ──► models.Project
                                                                                         │
            ┌──────────────────────────────────────────────────────────────────────────────┤
            ▼                                    ▼                                         ▼
 parsers/dax.py (tokenizer + call tree)   graph/model_graph.py (paths, cycles, SCC)   analyzers/inventory.py
            └──────────────► analyzers/semantic.py (reference resolution, measure deps, base tables, modifiers)
                                         │
     ┌───────────────┬───────────────────┼────────────────────┬──────────────────────┐
     ▼               ▼                   ▼                    ▼                      ▼
 model_rules     dax_rules         visual_rules          filters (investigate)   diff (change impact)
     └──── stage_model ────┘       └── stage_visual ──┘
                     │                     │            performance (Performance Analyzer)
                     └──────── findings/summary.finalize ───────┘
                                         │
                       reporting/render (Markdown · HTML · JSON) · reporting/merge
                                         │
                          cli.py  ·  entrypoints/ep_*.py (skill scripts)
```

## Layers

| Layer | Modules | Responsibility |
|---|---|---|
| Security | `security/safety.py` | Resolves the authorized root. Refuses reads outside it, symlinks pointing outside, sensitive files (`.env`, keys, `localSettings.json`, `cache.abf`) and oversized files. Output must be outside the project. Provides redaction helpers. |
| Discovery | `discovery/detector.py` | Finds `.pbip`, `*.Report` and `*.SemanticModel`, and flags `.pbix`. |
| Parsers | `parsers/tmdl.py`, `parsers/model_loader.py`, `parsers/pbir.py`, `parsers/dax.py` | Convert files into dataclasses (`models.py`). Tolerant: problems become `ParseIssue` records, never crashes. |
| Graph | `graph/model_graph.py` | Relationship graph with propagation semantics, path enumeration (allowed and blocked), cycle basis, roles (fact/dimension/bridge/disconnected) and Tarjan SCC for measure cycles. |
| Semantics | `analyzers/semantic.py` | Resolves DAX references against the model. Builds measure dependencies, base tables and filter modifiers. |
| Rules | `analyzers/model_rules.py`, `dax_rules.py`, `visual_rules.py`, `performance.py` | Produce `Finding` objects with evidence, status and severity. |
| Investigation | `analyzers/filters.py` | Question-driven filter propagation analysis with ranked hypotheses. |
| Impact | `analyzers/diff.py` | Token-level comparison and dependency-based impact. |
| Stages | `analyzers/stage_model.py`, `stage_visual.py`, `audit.py` | Shared orchestration used by both the CLI and the skill scripts (parity by construction). |
| Output | `findings/summary.py`, `findings/issues.py`, `findings/catalog.py`, `reporting/render.py`, `reporting/merge.py` | Deduplication, stable ordering, rule catalog, and Markdown/HTML/JSON rendering. |
| Interfaces | `cli.py`, `entrypoints/` | CLI commands and skill script entry points. |

## Determinism and evidence

- Finding IDs are `RULE-sha1(rule|path|object)[:8]`, so they stay stable across runs and machines.
- Paths in output are relative to the project root and use `/`. Absolute paths are never written to reports.
- Every finding carries `evidence`, a source path, a line number when known, `explanation`, `impact`,
  `recommendation` and `verification`.
- The agent's reasoning is kept separate from the engine's evidence. The engine produces evidence and ranked
  hypotheses; the skill instructs the agent to label its own reasoning.

## Agensi packaging

Agensi runs each script as an isolated temporary file. `tools/build_skill.py` bundles each
`entrypoints/ep_*.py` with its transitive `pbip_forensics` dependencies:

1. Resolves imports with `ast` and orders the modules topologically.
2. Removes internal imports and docstrings. `#` comments in Portuguese are kept.
3. Fails on name collisions.
4. Compiles the result.
5. Scans for forbidden patterns (network, subprocess, eval/exec, deletion, base64, `os.environ`).

`tests/integration/test_skill_scripts.py` runs every bundled script alone, copied to a temporary folder
under `python -I`. It compares the results with the engine: findings, dependency map, inventory, performance
and diff. `tools/package_agensi.py` builds and validates the ZIP.
