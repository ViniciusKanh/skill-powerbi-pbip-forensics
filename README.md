<div align="center">

<img src="docs/assets/logo-512.png" alt="Power BI PBIP Forensics" width="220">

# Power BI PBIP Forensics

### Ask your AI agent *why* your Power BI report behaves the way it does, and get answers backed by evidence from your project files.

![Version](https://img.shields.io/badge/version-1.0.0-0B5ED7)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-93%20passing-2EA44F)
![Dependencies](https://img.shields.io/badge/dependencies-none-2EA44F)
![Mode](https://img.shields.io/badge/mode-read--only%20%7C%20offline-F2A900)
![License](https://img.shields.io/badge/license-proprietary-6C757D)

[What it does](#-what-it-does) •
[Quick start](#-quick-start) •
[Ask it](#-what-you-can-ask) •
[How it works](#-how-it-works) •
[Scripts](#-skill-scripts) •
[Safety](#-safety-and-privacy) •
[Limitations](#-limitations) •
[Developers](#-for-developers)

</div>

---

## 🔎 What it does

**Power BI PBIP Forensics** is an AI agent skill, with a Python engine behind it, that diagnoses Power BI
projects saved in the **PBIP** format. It reads the report definition (**PBIR**) and the semantic model
(**TMDL** or `model.bim`) as text. It builds the relationship graph and the DAX dependency graph, and explains
problems such as:

- 🔗 **Filters that do not propagate**: inactive relationships, one-way relationships blocking the path, disconnected tables.
- 🧮 **DAX problems**: missing references, circular dependencies, `ALL`/`REMOVEFILTERS` overriding slicers, totals that differ from the visible rows, costly patterns.
- 📊 **Broken visuals**: fields that no longer exist in the model, custom visuals that cannot be interpreted.
- 🐢 **Slow visuals**: ranked from a Performance Analyzer export (*preview*).
- 🔀 **Change impact**: what changed between two versions, and which measures and visuals to retest.

Every finding states:

| | |
|---|---|
| **Where** | File path, line and object |
| **Why** | The evidence that triggered it |
| **How sure** | `confirmed` · `potential` · `inconclusive` |
| **What to do** | A suggested fix |
| **How to verify** | A check you can run in Power BI Desktop |

<p align="center">
  <img src="docs/assets/report-preview.png" alt="Audit report preview" width="820"><br>
  <sub>HTML audit report generated from the bundled synthetic project.</sub>
</p>

## 🚀 Quick start

### Use it as an agent skill

1. Get the skill: buy it on **Agensi**, or use the folder `agensi/powerbi-pbip-forensics/` from this repository.
2. Install it where your agent loads skills. For **Claude Code**:

   ```powershell
   # Windows (PowerShell)
   Copy-Item -Recurse .\agensi\powerbi-pbip-forensics "$env:USERPROFILE\.claude\skills\powerbi-pbip-forensics"
   ```

   ```bash
   # Linux / macOS
   cp -r agensi/powerbi-pbip-forensics ~/.claude/skills/powerbi-pbip-forensics
   ```

   For other agents, point them to `SKILL.md`. Any agent that can read Markdown and run local Python scripts can use the skill.
3. Open your agent in the folder that contains your `.pbip` project and ask a question (see below).
   The agent asks for permission to read the folder, runs the right scripts, and answers with evidence.

> **Requirements:** Python **3.11+** (standard library only) and a report saved as a Power BI project
> (*File → Save as → Power BI project (.pbip)*). Binary `.pbix` files are not supported.

### Or run the scripts yourself

```powershell
$S = ".\agensi\powerbi-pbip-forensics\scripts"
$P = "C:\BI\MyProject"        # your PBIP folder (read-only)
$O = "C:\BI\audit"            # output folder, must be outside the project

py $S\pbip_model_audit.py  --project $P --output $O
py $S\pbip_visual_deps.py  --project $P --from-table Customer --to-table Account --output $O
py $S\pbip_report.py       --input $O\model_audit.json $O\visual_deps.json --output $O\report
```

Open `C:\BI\audit\report\audit-report.html`. Add `--lang pt-BR` for Portuguese headings.

## 💬 What you can ask

| You ask the agent | It checks |
|---|---|
| *"Why is the Customer Accounts table showing accounts unrelated to the selected customer?"* | Relationship paths hop by hop, inactive or one-way relationships, visual bindings |
| *"Why does **Total Revenue** ignore my slicer?"* | `ALL` / `REMOVEFILTERS` / `CROSSFILTER` in the measure and its dependencies |
| *"My total is different from the sum of the rows. What should I check?"* | Non-additive patterns (`IF` on measures, `DISTINCTCOUNT`, `HASONEVALUE`), many-to-many relationships |
| *"Which visuals are slowing this page down?"* | Measured DAX query, visual display and *Other* times from your Performance Analyzer export |
| *"Compare `v1` and `v2`. What do I need to retest?"* | Changed measures, columns and relationships, and every dependent measure and visual |
| *"Audit this project before I publish it."* | All rules, merged into one Markdown/HTML report |

### Example answer

This is real script output from the bundled example, `examples/synthetic_project`:

```text
VIS006  HIGH  potential  Unrelated tables combined in 'Customer Accounts' (tableEx): 'Account' and 'Customer'
        No active relationship path between them in either direction
        → ContosoRetail.Report/definition/pages/overview01/visuals/v_table_accounts/visual.json

MOD002  LOW   potential  Inactive relationship not activated by any measure: Account -> Customer
        'Account'[CustomerKey] (many) -> 'Customer'[CustomerKey] (one) · isActive: false
        → ContosoRetail.SemanticModel/definition/relationships.tmdl:27

Investigation  Customer → Account
  BLOCKED PATH: 'Customer' -> 'Account' via 'Account'[CustomerKey] -> 'Customer'[CustomerKey] [INACTIVE]
  #1 [high confidence] Inactive relationship on the only path from 'Customer' to 'Account'.
     Verify: confirm isActive=false in Model view; test a measure with USERELATIONSHIP(...).
```

The agent keeps **script evidence** separate from **its own reasoning**, and always states the limits of the
analysis (template: [`templates/investigation-response.md`](agensi/powerbi-pbip-forensics/templates/investigation-response.md)).

## ⚙️ How it works

```mermaid
flowchart LR
    A[PBIP folder<br/>read-only] --> B[Discovery<br/>.pbip · .Report · .SemanticModel]
    B --> C[Parsers<br/>PBIR · TMDL · model.bim]
    C --> D[DAX tokenizer<br/>call tree · references]
    C --> E[Relationship graph<br/>paths · cycles · roles]
    D --> F[Rules<br/>MOD · DAX · VIS · PERF]
    E --> F
    G[Performance Analyzer<br/>export .json] --> F
    F --> H[Findings with evidence<br/>+ ranked hypotheses]
    H --> I[Report<br/>Markdown · HTML · JSON]
```

- **Real parsing, not guessing.** The TMDL parser follows indentation, so it handles multi-line expressions,
  triple-backtick blocks and quoted names. The DAX tokenizer respects strings, comments and `[references]`.
  PBIR fields follow Microsoft's published JSON schemas.
- **Graph algorithms.** Filter paths are direction-aware. Blocked paths are explained hop by hop. Ambiguous
  loops are separated from harmless ones, and measure cycles are found with Tarjan's algorithm.
- **Honest statuses.** `confirmed` means proven by the files or measured in a log. `potential` means a risk to
  verify. `inconclusive` means the engine could not interpret it. There are no invented percentages and no
  invented timings.

Full rule list: [docs/diagnostic-rules.md](docs/diagnostic-rules.md).

## 🧰 Skill scripts

Each script is **standalone**: one file, Python standard library only, no network. It reads only the paths you
pass, writes JSON only to `--output`, and works on Windows, Linux and macOS.

| Script | Purpose | Main arguments |
|---|---|---|
| `pbip_inspect.py` | Inventory of reports, pages, visuals, tables, measures, relationships and data-source connectors | `--project` |
| `pbip_model_audit.py` | Relationship and model structure checks plus DAX static analysis | `--project` |
| `pbip_visual_deps.py` | Page → Visual → Field → Table map, broken bindings, filter investigation | `--project` `--from-table` `--to-table` `--measure` `--visual` |
| `pbip_perf_log.py` | Ranks visuals by measured duration *(preview)* | `--input` `--medium-ms` `--high-ms` |
| `pbip_diff.py` | Changes between two versions and their impact | `--before` `--after` |
| `pbip_report.py` | Merges the JSON outputs into Markdown, HTML and JSON | `--input …` `--format` `--lang en\|pt-BR` |

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | OK |
| `2` | Invalid input |
| `3` | Size limit exceeded |
| `4` | Refused by the safety policy |
| `5` | Invalid performance log |
| `10` | Internal error |

## 🛡️ Safety and privacy

- **Read-only.** The project is never modified, and reports must be written outside it.
- **Scope-locked.** Only the folder you authorize is read. Symbolic links that point outside it are not followed.
- **No secrets.** `.env`, keys, certificates, `localSettings.json` and `cache.abf` are never opened. Only connector
  names (for example `Sql.Database`) are reported, never connection strings or credentials.
- **No execution.** DAX, M and JSON are parsed as data and never evaluated.
- **No network.** Everything runs locally and offline.
- **Untrusted content.** Text inside the project, such as measure names and descriptions, is treated as data and
  never as instructions. HTML output is escaped.

## ⚠️ Limitations

- **Static analysis.** No DAX is executed and no data is read, so the skill never claims values or totals.
- **Formats.** PBIX/PBIT are not supported. Support for the older PBIR-Legacy report format is best-effort.
- **Not modelled:** calculation groups, row-level security, `TREATAS` virtual relationships, and visual
  interactions or bookmarks.
- **Performance Analyzer (preview).** Validated with synthetic exports only. Compatibility with real Power BI
  Desktop exports is still being validated.
- **Language.** Finding texts are in English. Report headings are available in English and Brazilian Portuguese.

Details: [docs/limitations.md](docs/limitations.md).

---

## 👩‍💻 For developers

<details>
<summary><b>Engine CLI</b></summary>

```bash
pip install -e ".[dev]"
pbip-forensics scan        --project ./examples/synthetic_project
pbip-forensics audit       --project ./examples/synthetic_project --output ./reports [--performance perf.json] [--lang pt-BR] [--fail-on HIGH]
pbip-forensics investigate --project ./examples/synthetic_project --from-table Customer --to-table Account
pbip-forensics performance --input ./examples/sample_performance/performance.json
pbip-forensics diff        --before ./examples/synthetic_project --after ./examples/synthetic_project_v2
pbip-forensics report      --input ./reports/findings.json --format html
```

`--fail-on` returns exit code 1 when there are findings at or above the given severity, which is useful in CI.
</details>

<details>
<summary><b>Repository layout</b></summary>

```text
src/pbip_forensics/     engine: security · discovery · parsers · graph · analyzers · findings · reporting · cli
agensi/powerbi-pbip-forensics/   the skill: SKILL.md · scripts/ (generated) · references/ · templates/
tools/                  build_skill · package_agensi · make_fixtures · run_demo · gen_docs · script_metrics
tests/                  unit · integration (including isolated script parity) · fixtures (synthetic)
examples/               synthetic projects · sample Performance Analyzer log · real sample reports
docs/                   architecture · formats · rules · limitations · validation · Agensi docs
```
</details>

<details>
<summary><b>Tests and packaging</b></summary>

```bash
python -m pytest -o addopts="" -q     # 93 tests
ruff check src tests tools && mypy
python tools/build_skill.py           # regenerate standalone scripts from the engine
python tools/package_agensi.py        # build and validate dist/powerbi-pbip-forensics-v1.0.0.zip
```

Measured results:

| Environment | Result |
|---|---|
| CPython 3.11 and 3.13 (Linux) | 93 tests passing; 87% coverage |
| Windows, CPython 3.13 | 92 passed, 1 symlink test skipped |

Each generated script is also run alone, under `python -I`, and its output is compared with the engine's.
See [docs/validation-results.md](docs/validation-results.md).
</details>

### Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | Modules, data flow, skill bundling |
| [Supported formats](docs/supported-formats.md) | PBIP / PBIR / TMDL / TMSL / Performance Analyzer fields and versions |
| [Diagnostic rules](docs/diagnostic-rules.md) | Every rule, its severity, status and false-positive safeguards |
| [Limitations](docs/limitations.md) | What is out of scope |
| [Validation results](docs/validation-results.md) | Measured tests, coverage, timing, parity |
| [SKILL.md](agensi/powerbi-pbip-forensics/SKILL.md) | Operational instructions for agents |
| [Publishing on Agensi](docs/PUBLISH_AGENSI.md) | Submission and post-publication test |
| [Changelog](CHANGELOG.md) | Release history |

## 📄 License

Copyright © 2026 **Vinicius de Souza Santos**. All rights reserved. This is proprietary software, and access to
this repository does not grant any right to use, copy or redistribute it. See [LICENSE](LICENSE).

Power BI, PBIP, PBIR, TMDL and DAX are Microsoft technologies. This project is not affiliated with or endorsed by
Microsoft.

<div align="center">
<sub>Made by <a href="https://github.com/ViniciusKanh">Vinicius de Souza Santos</a> · v1.0.0</sub>
</div>
