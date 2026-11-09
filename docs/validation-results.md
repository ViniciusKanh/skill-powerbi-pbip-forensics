# Validation results (observed, v1.0.0)

Recorded on 2026-11-08/09 (UTC) in the build environment: Linux x86-64, CPython **3.13.18** and **3.11.18**.
All values below were measured, not estimated. Scripts print a clear error and exit with code 2 on Python older than 3.11 (checked on CPython 3.10.12). Reproduce them with the commands shown.

## Automated tests

```bash
python -m pytest -o addopts="" -q --cov=pbip_forensics --cov-report=term
python3.11 -m pytest -o addopts="" -q
ruff check src tests tools
mypy
```

| Metric | Result |
|---|---|
| Tests (CPython 3.13.18) | **93 passed**, 0 failed, 0 skipped |
| Tests (CPython 3.11.18) | **93 passed**, 0 failed, 0 skipped |
| Success rate | 100% |
| Coverage (statements + branches, in-process) | **87%** |
| `ruff` | All checks passed |
| `mypy` (`disallow_untyped_defs`) | No issues in 42 source files |

Coverage excludes `entrypoints/*` and `__main__.py`. Those run as bundled scripts in isolated subprocesses
(20 parity and isolation tests in `tests/integration/test_skill_scripts.py`), so in-process coverage cannot
see them. The modules with the lowest coverage are `parsers/model_loader.py` (72%), `parsers/pbir.py` (73%)
and `cli.py` (76%). The uncovered lines are mainly defensive error branches.

## Scenario coverage

| # | Scenario | Fixture | Test |
|---|---|---|---|
| 1 | Valid simple PBIP | `simple_valid` | `test_simple_valid_project_has_no_false_positives` |
| 2 | Inactive relationship | `inactive_relationship` | `test_inactive_relationship_detected_and_unactivated` |
| 3 | Ambiguous filter path | `ambiguous_path` | `test_ambiguous_path_detected` |
| 4 | Disconnected dimension | `disconnected_dimension` | `test_disconnected_dimension` |
| 5 | Confirmed missing reference | `dax_patterns` | `test_missing_references_confirmed` |
| 6 | Costly DAX pattern | `dax_patterns` | `test_costly_and_context_patterns` |
| 7 | Measure modifying filter context | `dax_patterns` | `test_costly_and_context_patterns`, `test_filter_investigation_measure_modifier` |
| 8 | Visual with missing reference | `visual_issues` | `test_visual_issues_missing_custom_and_malformed` |
| 9 | Uninterpretable custom visual | `visual_issues` | same as above (VIS003 inconclusive) |
| 10 | Malformed PBIR file | `visual_issues/.../broken/visual.json` | same as above (PRS001) |
| 11 | Multi-line TMDL expressions (```, CRLF, descriptions) | `multiline_tmdl` | `test_multiline_backticks_descriptions_crlf` |
| 12 | Identifiers with spaces, quotes and Unicode | `special_identifiers` | `test_special_identifiers_unicode`, `test_unicode_paths` |
| 13 | Performance log with multiple visuals | `performance/multi_visual.json` | `test_multi_visual_log_breakdown` |
| 14 | Version diff with modified measure | `diff_before` / `diff_after_measure` | `test_diff_measure_modified_with_impact` |
| 15 | Relationship change impacting visuals | `diff_after_relationship` | `test_diff_relationship_change_impact` |
| 16 | No performance log | `simple_valid` | `test_audit_without_log_states_limitation` |
| 17 | Empty directory | runtime `tmp_path` | `test_empty_directory` |
| 18 | Invalid paths | runtime | `test_error_exit_codes`, `test_script_errors` |
| 19 | Oversized files | runtime | `test_large_file_limit`, `test_file_size_limit_cli` |
| 20 | Attempts to escape the authorized scope | `escape_bypath`, runtime symlink, output inside project | `test_bypath_escape_is_blocked`, `test_symlink_outside_scope_not_followed`, `test_output_inside_project_refused`, `test_read_outside_scope_refused` |
| + | Secrets and prompt-injection text | `security_cases` | `test_sensitive_files_are_never_read`, `test_secrets_and_injection_text_not_leaked_as_instructions` |
| + | PBIR-Legacy and TMSL | `legacy_pbir` | `test_legacy_and_tmsl_support` |
| + | PBIX only | `pbix_only` | `test_pbix_only_is_flagged_unsupported` |
| + | Read-only guarantee | example project | `test_audit_does_not_modify_project` (size and mtime snapshot) |

## Negative scenarios (false-positive checks)

| Negative case | Observed false diagnoses |
|---|---|
| `simple_valid`: valid model and report | **0** findings of any severity |
| `loop_not_ambiguous`: loop without competing directed paths | **0** HIGH; MOD006 reported as INFO only, plus DAX011 INFO (no visuals) |
| `diff_before` vs identical copy | **0** changes |
| `diff_after_format`: whitespace and comment change | **0** logic changes (`modified-formatting` only, no impacts) |
| DAX columns created in-expression (`ADDCOLUMNS "Rev"`, `GENERATESERIES [Value]`) | **0** DAX001 |
| Column predicate `CALCULATE([m], T[c] > 10)` | **0** DAX003 |
| Bracket text inside strings and comments, triple-backtick measure | **0** spurious references |
| `RANKX(ALL(Customer), ...)` (table expression, not a CALCULATE modifier) | **0** DAX006 |
| Single-table model | **0** MOD008 |

## Processing time (engine, in-process)

| Project | Time | Findings | Confirmed | Potential | Inconclusive | Parse errors |
|---|---|---|---|---|---|---|
| `examples/synthetic_project` | 7.6 ms | 25 | 4 | 20 | 1 | 0 |
| `examples/synthetic_project_v2` | 6.4 ms | 22 | 4 | 17 | 1 | 0 |
| test fixtures (each) | 0.1–2.6 ms | 0–16 | | | | 1 (intentional, `visual_issues`) |

With the sample Performance Analyzer log, the synthetic audit produces 28 findings: 7 confirmed, 20 potential
and 1 inconclusive (CRITICAL 0, HIGH 7, MEDIUM 7, LOW 7, INFO 7).

**Bundled scripts, run as isolated temporary files** (`tools/package_agensi.py`), wall-clock per process
including interpreter start:

| Script | Time |
|---|---|
| inspect | 0.088 s |
| model_audit | 0.082 s |
| visual_deps | 0.070 s |
| perf_log | 0.043 s |
| diff | 0.070 s |

## Parsing errors

- **0** parse errors on valid fixtures and examples.
- **0** unknown TMDL keywords on the generated fixtures.
- **1** intentional malformed `visual.json`, which is detected and reported as PRS001.
- No real-world Microsoft-generated PBIP projects were available in the build environment. The parsers were
  validated against fixtures built from the published schemas and the TMDL documentation, not against a
  corpus of real projects.

## Engine and script parity

`tests/integration/test_skill_scripts.py` copies each generated script alone into a temporary folder and runs
it with `python -I`. Results:

- **Findings** (ID, severity, status, evidence) from `pbip_model_audit.py` + `pbip_visual_deps.py` match
  `run_audit()` on 8 projects.
- **Dependency map:** identical to the engine on the same 8 projects.
- **Inventory** (`pbip_inspect.py`): identical on 4 projects.
- **Performance** (`pbip_perf_log.py`) and **change impact** (`pbip_diff.py`): identical to the engine.
- **Merged report** (`pbip_report.py`): finding IDs match the full CLI audit with the performance log.

## Agensi package

The package is validated by `tools/package_agensi.py`, which writes `dist/validation-report.json`. See
`docs/agensi-compliance.md`.

Script sizes:

| Script | Total bytes | Code bytes without comments | Logic bytes without text literals* |
|---|---|---|---|
| pbip_inspect.py | 85,824 | 73,917 | 64,156 |
| pbip_model_audit.py | 109,933 | 94,347 | 74,278 |
| pbip_visual_deps.py | 118,793 | 102,121 | 80,827 |
| pbip_perf_log.py | 24,188 | 21,718 | 17,383 |
| pbip_diff.py | 90,121 | 78,195 | 68,322 |
| pbip_report.py | 34,782 | 32,673 | 24,621 |

\*Measured with `tools/script_metrics.py`. Tokens are joined with spaces, so these are upper bounds.
**Only `pbip_perf_log.py` is under the ~20 KB logic guideline.**
