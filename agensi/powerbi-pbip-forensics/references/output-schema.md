# Output schema (JSON)

Every script writes one JSON document. These are the common top-level keys:

| Key | Description |
|---|---|
| `tool`, `version`, `script`, `project`, `generated_at` | Provenance. `project` is the folder name only, never an absolute path. |
| `findings[]` | Finding objects (see below), sorted by severity, then status, then ID. |
| `severity_breakdown`, `status_breakdown` | Counts per CRITICAL/HIGH/MEDIUM/LOW/INFO and confirmed/potential/inconclusive. |
| `limitations[]` | Statements that must be carried into the final answer. |

Script-specific keys:

| Script | Keys |
|---|---|
| `pbip_inspect.py` | `inventory` (`counts`, `models[]`, `reports[]`, `skipped_items[]`), `parse_issues[]` |
| `pbip_visual_deps.py` | `dependency_map[]` (report, page, visual, visual_title, visual_type, usage, role, kind, table, field, status, detail, path), `investigations[]` |
| `pbip_perf_log.py` | `performance` (`version`, `event_count`, `user_actions`, `visuals[]`, `warnings[]`), `performance_source` |
| `pbip_diff.py` | `change_impact` (`summary`, `changes[]`, `impacts[]`, `note`) |

## Finding object

| Field | Meaning |
|---|---|
| `id` | Stable ID: `<RULE>-<8 hex>`, derived from rule, path and object. It is identical across runs. |
| `rule_id` | Rule code (see diagnostic-rules.md). |
| `title`, `category` | Short description and area. |
| `severity` | CRITICAL, HIGH, MEDIUM, LOW or INFO. |
| `status` | `confirmed` (structural proof), `potential` (rule-based risk) or `inconclusive` (could not be interpreted). |
| `evidence[]` | Concrete facts taken from the files or the log. |
| `path`, `line`, `object_ref` | Source location relative to the project root, line number when available, and the object identifier. |
| `explanation`, `impact`, `recommendation`, `verification` | Technical explanation, possible impact, suggested fix and how to verify it in Power BI. |

## Investigation object

| Field | Meaning |
|---|---|
| `from_table`, `targets[]`, `measure`, `visual` | The question in structured form. |
| `evidence[]` | Deterministic lines: `ACTIVE PATH` / `BLOCKED PATH` with each hop and its state, plus measure modifiers. |
| `hypotheses[]` | `rank`, `hypothesis`, `confidence` (high/medium/low), `justification`, `verification_steps[]`. |
| `note` | Reminder that hypotheses require verification in Power BI. |

Confidence is qualitative. **High** means direct structural evidence in the files. **Medium** means the
structure allows it but intent or data decides. **Low** means the files show no blocker and the
hypothesis depends on data or interactions.
