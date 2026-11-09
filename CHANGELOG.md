# Changelog

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
