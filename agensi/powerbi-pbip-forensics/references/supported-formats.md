# Supported formats

This page lists what Power BI PBIP Forensics 1.0.0 reads, which fields it uses, and where support is limited.
Sources were checked on 2026-11-08 (Microsoft Learn pages and the public JSON schemas at
`developer.microsoft.com/json-schemas/fabric/...`).

## Support matrix

| Artifact | Status | Notes |
|---|---|---|
| `.pbip` (pbipProperties 1.0.0) | Supported | `artifacts[].report.path` is checked; a missing folder is reported (PRS002). |
| `*.Report/definition.pbir` (definitionProperties 2.0.0) | Supported | `version` and `datasetReference.byPath.path` are read. A `byConnection` string is never copied; the engine records only that it is `byConnection`. |
| PBIR (`definition/` folder, version 4.0+) | Supported | `version.json`, `report.json`, `reportExtensions.json`, `pages/pages.json`, `pages/*/page.json`, `pages/*/visuals/*/visual.json`. |
| PBIR-Legacy (`report.json` at the report root) | **Limited** | The schema is not publicly documented. Best-effort extraction of `sections[].visualContainers[].config.singleVisual.prototypeQuery`. Visual filters and formatting are not analyzed (PRS004). |
| `*.SemanticModel/definition.pbism` (definitionProperties 1.0.0) | Supported | `version` only. |
| TMDL (`definition/*.tmdl`) | Supported | See the TMDL subset below. `cultures/` is skipped because it holds linguistic metadata only. |
| TMSL (`model.bim`) | Supported (subset) | `model.tables[].columns/measures/partitions/hierarchies`, `model.relationships`, `roles`, `expressions`. |
| Performance Analyzer export (`.json`) | Supported, **format not documented on Learn** | See the dedicated section below. |
| `.pbix` / `.pbit` | Not supported | Detected and reported (PRS003). Save the file as a project (`.pbip`) first. |
| `.pbi/localSettings.json`, `cache.abf` | Never read | Treated as local or sensitive and skipped by the security layer. |
| `diagramLayout.json`, `mobile.json`, bookmarks | Ignored | Not needed for diagnostics. |

## TMDL subset

Implemented from https://learn.microsoft.com/analysis-services/tmdl/tmdl-overview:

- Indentation defines the hierarchy. A tab is one level. Four spaces are also accepted as one level, as a tolerance.
- `key: value` sets a non-expression property. Values in optional double quotes are unquoted, and `""` is unescaped.
- `key = expression` and `objectType Name = expression` set expression properties. Multi-line expressions
  start on the next line and must be indented deeper. Expressions delimited by triple backticks are read verbatim.
- Names in single quotes use `''` as the escape. Qualified references can be written as `Table.Column` or
  `'Table X'.'Column Y'`.
- `///` descriptions and `ref` lines are ignored. Partial declarations (the same table in several files) are merged.
- Objects and properties used:
  - `table`: `isHidden`
  - `column`: `dataType`, `isHidden`, calculated `= expr`
  - `measure`: `= expr`, `formatString`, `displayFolder`, `isHidden`
  - `partition`: `= m|calculated|...`, `mode`, `source =`
  - `hierarchy`
  - `calculationGroup`
  - `relationship`: `fromColumn`, `toColumn`, `isActive`, `crossFilteringBehavior`, `fromCardinality`, `toCardinality`
  - top-level `expression`
  - top-level `role`
- Relationship property names come from the Tabular Object Model (`SingleColumnRelationship`). The TMDL
  overview page shows only `fromColumn`/`toColumn`, so the other names were not confirmed against a
  Microsoft-published TMDL sample in this release. Defaults: `isActive=true`,
  `crossFilteringBehavior=oneDirection`, `fromCardinality=many`, `toCardinality=one`.
- Unknown keywords are recorded as `unknown-keyword` issues and never stop parsing.

## PBIR fields used

- `visual.json` (visualContainer 2.4.0):
  - `name` and `visualGroup`
  - `visual.visualType`
  - `visual.query.queryState.<role>.projections[].field`
  - `visual.query.sortDefinition.sort[].field`
  - `filterConfig.filters[].field`
  - title text from `visual.visualContainerObjects.title[0].properties.text.expr.Literal.Value`
- Field expressions (semanticQuery 1.3.0):
  - `Column`, `Measure`, `Aggregation` (with `Function` 0–8), `HierarchyLevel`
  - `PropertyVariationSource` (auto date hierarchies)
  - `SourceRef.Entity`, or `SourceRef.Source` resolved through `From` aliases (legacy only)
  - `NativeVisualCalculation` is recognized but not resolved (visual calculation).
- `page.json` (page 2.0.0): `name`, `displayName` and `filterConfig.filters[]`.
- `pages.json` (pagesMetadata 1.0.0): `pageOrder`.
- `report.json`: `filterConfig.filters[]`, `publicCustomVisuals`.
- `reportExtensions.json`: `entities[].name`, `entities[].measures[].name` (report-level measures accepted as valid bindings).

Visual types outside the built-in list are treated as custom or unrecognized. They are never reported as an
error. A limitation is recorded only when no bindings can be read (VIS003).

## Performance Analyzer export

Microsoft Learn (desktop-performance-analyzer) documents the export action and the duration categories:
DAX query, Direct query, Visual display, Other and Evaluated parameters. It does **not** document the JSON
layout. Learn refers to a "Power BI Performance Analyzer Export File Format" document in the
`powerbi-desktop-samples` repository, which could not be retrieved during development.

The reader expects:

```json
{"version": "1.1.0", "events": [
  {"name": "Visual Container Lifecycle", "id": "...", "start": "ISO-8601", "end": "ISO-8601",
   "metrics": {"visualTitle": "...", "visualId": "...", "visualType": "..."}},
  {"name": "Query", "id": "...", "parentId": "<lifecycle id>", "start": "...", "end": "..."},
  {"name": "Execute DAX Query", "parentId": "<query id>", "metrics": {"QueryText": "...", "RowCount": 0}},
  {"name": "Render", "parentId": "<lifecycle id>", "start": "...", "end": "..."}
]}
```

Mapping:

| Duration column | Computed as |
|---|---|
| DAX query | Sum of `Execute DAX Query` |
| Direct query | Sum of `Execute Direct Query` |
| Visual display | Sum of `Render` |
| Other | Lifecycle total minus the measured components (derived; includes queueing) |

Tolerance:

- Malformed events, events without an `end`, and `parentId` references that are not in the file are counted and reported as warnings.
- A file without an `events` list is rejected (exit code 5).

**Verification pending:** validate against a real export from the current Power BI Desktop before the commercial
release (see `docs/limitations.md`).
