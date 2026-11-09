# Known limitations (v1.0.0)

## Analysis scope

- **Static analysis only.** DAX and M are never executed and no data is read. The engine cannot report values,
  totals or row counts, and does not claim them.
- **Filter propagation comes from metadata.** Paths are computed from `isActive`, `crossFilteringBehavior` and
  cardinality, adjusted for USERELATIONSHIP, CROSSFILTER and ALL/REMOVEFILTERS found in DAX. The engine does not
  model:
  - expanded-table semantics in full;
  - TREATAS-based virtual relationships;
  - calculation groups;
  - row-level security;
  - limited (cross-island) relationships;
  - query plans.
- **DAX analysis is structural.** The tokenizer and call tree cover the syntax used by the rules: strings,
  comments, quoted names, bracket references and function calls. It is not a full DAX grammar. DEFINE blocks,
  user-defined functions and some newer syntax (for example, visual calculations) are tokenized but not
  interpreted. Unresolved names created dynamically outside the recognized patterns may be reported as
  potential.
- **Unqualified column references** that exist in several tables are not attributed to a table.
- **Base tables of a measure** are approximated as tables referenced outside CALCULATE filter arguments and
  outside filter modifiers.
- **Visual filters:** only the filtered field is used. Filter conditions (values, TopN, relative date) are
  not evaluated.
- **Interactions:** Edit interactions, bookmarks, drill-through and sync slicers are not analyzed. They are
  mentioned as hypotheses when no structural cause is found.
- **Unused measures (DAX011)** are reported only when every report bound to the model is PBIR and fully
  interpretable. Reports connected to the published model from elsewhere are never visible.
- **Multi-model projects:** each report is validated against the model it references by path. Change-impact
  analysis computes impacts for the first semantic model only.

## Formats

- **PBIX/PBIT binaries are not supported.**
- **PBIR-Legacy** support is limited and best-effort, because its schema is undocumented.
- **TMDL relationship property names** beyond `fromColumn`/`toColumn` come from the Tabular Object Model. They
  are not taken from a Microsoft TMDL sample.
- **Performance Analyzer export layout** is not documented on Microsoft Learn. The reader was validated with
  synthetic files that follow the commonly exported structure (`events`, `parentId`, `metrics`).
  **It must be validated against a real export from the current Power BI Desktop before release.**
- **Indentation:** TMDL files indented with spaces are accepted (4 spaces = 1 level). Other custom indentation
  settings are not.

## Packaging (Agensi)

- **Script size:** Agensi recommends keeping each script's logic under about 20 KB. Five of the six bundled
  scripts exceed this, because each one embeds the full parsers so it can run alone, as Agensi requires.
  Sizes are measured in `docs/validation-results.md`. A v1.1 option is a staged pipeline: the inspect
  script emits a normalized inventory, and the analysis scripts read that JSON instead of re-parsing.
- **Platform review:** the security scan and approval are performed by Agensi and cannot be reproduced locally.

## Environment

- **Python:** 3.11+ is required. The suite was tested on Linux with CPython 3.11 and 3.13.
- **Windows:** path handling uses `pathlib` and POSIX-style relative paths in output. Verified on Windows with CPython 3.13.13 (92 passed, 1 symlink test skipped).
- **Report language:** Markdown/HTML headings support English and Brazilian Portuguese. Finding texts are in
  English only.
