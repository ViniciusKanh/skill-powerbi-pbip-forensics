# Agensi listing: Power BI PBIP Forensics

## Name

Power BI PBIP Forensics

## Summary (≤ 300 characters)

Read-only forensic audit for Power BI PBIP/PBIR/TMDL projects. Finds broken bindings, missing DAX references,
inactive or ambiguous relationships, filters that cannot propagate, and slow visuals from Performance Analyzer
logs. Every finding comes with evidence, a file path and verification steps.

(The summary is 297 characters.)

## Description

**Power BI PBIP Forensics** lets your AI agent diagnose Power BI projects from their files instead of guessing.
It reads projects saved in the Power BI Project format, which covers the report definition (PBIR) and the
semantic model (TMDL or `model.bim`). Six standalone Python scripts parse those files and return findings
backed by evidence.

**How it works**

1. The agent asks permission to read your project folder and picks the scripts that match your question.
2. The scripts build an inventory, a relationship graph and a DAX dependency graph. They then apply
   documented diagnostic rules.
3. Each finding includes:
   - a stable ID, severity (CRITICAL to INFO) and status (`confirmed`, `potential` or `inconclusive`);
   - evidence lines, the file path and the line number when available;
   - impact, a suggested fix and how to verify it in Power BI Desktop.
4. For filter problems, an investigation lists every active and blocked path hop by hop and ranks root-cause
   hypotheses by confidence (high, medium or low), with justification for each.
5. A report script merges everything into Markdown, static HTML or JSON.

**Limits, stated plainly:**

- It is static analysis. DAX is never executed and no data is read, so it never states values or totals.
- Performance numbers come only from a Performance Analyzer export that you provide.
- PBIX binaries are not supported; save the file as a PBIP project first.
- PBIR-Legacy reports get best-effort support only.

## Target audience

- Power BI developers and BI analysts who maintain PBIP projects in Git.
- Analytics engineers who review pull requests that change semantic models or reports.
- Consultants who audit client reports before go-live.
- Teams that use AI coding agents (Claude Code, Codex-style agents) on their BI repositories.

## Problems solved

- "Why does this table show customers or accounts that are not related to my selection?"
- "Why does this measure ignore my slicer?"
- "Why is the total different from the sum of the visible rows?"
- "Which visuals are slowing down this page?" (with a Performance Analyzer export)
- "What will this change to a measure or relationship affect?"
- "Which visuals are broken after we renamed or removed fields?"

## Key features

- Project discovery and inventory: reports, pages, visuals, tables, columns, measures, relationships, filters
  and data-source connector names.
- Relationship analysis:
  - inactive relationships;
  - bidirectional and many-to-many relationships;
  - ambiguous active paths, kept separate from harmless loops;
  - disconnected tables;
  - broken references;
  - key type mismatches.
- DAX static analysis with a real tokenizer:
  - missing references and circular dependencies;
  - FILTER over tables inside CALCULATE;
  - nested iterators and context transition over fact tables;
  - filter-context modifiers (ALL, REMOVEFILTERS, ALLSELECTED, CROSSFILTER, USERELATIONSHIP);
  - totals that differ from row sums;
  - unsafe division.
- Visual dependency map (Page → Visual → Field → Table) with broken-binding detection.
- Filter-propagation investigation with ranked, justified hypotheses.
- Performance Analyzer log ranking with a breakdown of DAX query, Direct query, Visual display and Other time **(preview: validated with synthetic exports only; compatibility with real Power BI Desktop exports is still pending validation)**.
- Change impact between two project versions. Formatting-only changes are separated from logic changes.
- Reports in Markdown, HTML and JSON. Report headings can be in English or Brazilian Portuguese.

## Differentiators

- **Evidence, not opinions.** Every finding points to a file and an object, and lists the facts that
  triggered it.
- **Honest statuses.** `confirmed` means proven by structure; risks stay `potential`. No invented confidence
  percentages and no invented timings.
- **Real parsers.** Indentation-aware TMDL, a DAX tokenizer and call tree, and PBIR fields taken from
  Microsoft's published JSON schemas.
- **Safe for agents.** The skill is read-only and only reads folders you authorize. It skips `.env` files and
  keys, keeps only connector names (never connection strings), uses no network, and treats project text as
  untrusted data.
- **Standard library only.** Nothing to install beyond Python 3.11+.

## Example questions

- "Why is the Customer Accounts table showing unrelated accounts?"
- "My Total Revenue total doesn't match the rows. What should I check?"
- "Which visuals on this report are slow?" (attach the Performance Analyzer export)
- "Which relationships could stop the Customer filter from reaching Account?"
- "Compare `release-1.4` and `release-1.5` of this PBIP and tell me what to regression-test."

## See it in action (real output from the bundled synthetic project)

**Request:** "Why is the 'Customer Accounts' table showing accounts unrelated to the selected customer?"

**Commands run by the agent:**

```bash
python scripts/pbip_visual_deps.py --project examples/synthetic_project --from-table Customer --to-table Account --visual "Customer Accounts" --output out
python scripts/pbip_model_audit.py --project examples/synthetic_project --output out
```

**Script output (excerpt, unedited):**

```text
VIS006-94a723c2  HIGH  potential  Unrelated tables combined in 'Customer Accounts' (tableEx) on page 'Overview': 'Account' and 'Customer'
  evidence: Columns from 'Account' and 'Customer' in the same tableEx
            No active relationship path between them in either direction
  source:   ContosoRetail.Report/definition/pages/overview01/visuals/v_table_accounts/visual.json

MOD002  LOW  potential  Inactive relationship not activated by any measure: Account -> Customer
  evidence: 'Account'[CustomerKey] (many) -> 'Customer'[CustomerKey] (one) · isActive: false
            No USERELATIONSHIP reference found in any measure
  source:   ContosoRetail.SemanticModel/definition/relationships.tmdl:27

Investigation Customer -> Account
  Direction-compatible active paths 'Customer' -> 'Account': 0
  BLOCKED PATH: 'Customer' -> 'Account' via 'Account'[CustomerKey] (many) -> 'Customer'[CustomerKey] (one) [INACTIVE]
  #1 [high confidence] Inactive relationship on the only path from 'Customer' to 'Account'.
     Verify: confirm isActive=false in Model view; create a test measure with
     USERELATIONSHIP('Account'[CustomerKey], 'Customer'[CustomerKey]) and compare.
```

**Agent answer (shape):** The table cannot use the model to restrict accounts to the selected customer, because
the only relationship between `Account` and `Customer` is inactive and no measure activates it (VIS006, MOD002).
It recommends a verification sequence and offers two fixes: activate the relationship, or use a
USERELATIONSHIP measure. It states that this is static analysis and that no data values were read.

The same run also reported confirmed problems elsewhere in the project:

- a visual bound to a removed measure `Sales[Old Revenue]` (VIS002);
- a missing `[Total Cost]` reference in `Margin %` (DAX001);
- a USERELATIONSHIP call on columns with no relationship (DAX007).

## Limitations

- Static analysis only: no DAX execution and no data access.
- PBIX/PBIT are not supported; PBIR-Legacy support is limited.
- Calculation groups, RLS, TREATAS virtual relationships and visual interactions are not modelled.
- The Performance Analyzer JSON layout is not formally documented by Microsoft. The reader follows the standard
  export structure and reports anything it cannot read.
- Finding texts are in English; report headings can be in English or Brazilian Portuguese.
- Results cover only the folders you provide. Other reports connected to the published model are not seen.

## Requirements

- Python 3.11 or later; standard library only.
- An AI agent that can run local Python scripts and read local files (tested by running the scripts as isolated
  temporary files; not certified for any specific agent product).
- A Power BI project saved as PBIP (Power BI Desktop: File > Save as > Power BI project).
- Optional: a Performance Analyzer export (`.json`).
- Developed and tested on Linux with CPython 3.11 and 3.13. The code uses portable paths for Windows and macOS,
  and was also verified on Windows (CPython 3.13.13).

## Categories, tags and keywords

- **Categories (up to 3, choose from Agensi's list):** Data & Analytics (primary), Developer Tools, Code Review / QA.
  Map these to the closest available names when submitting.
- **Tags:** power-bi, pbip, pbir, tmdl, dax, semantic-model, data-modeling, bi-audit, performance, root-cause-analysis.
- **Keywords:** Power BI, PBIP, PBIR, TMDL, DAX, relationships, filter propagation, Performance Analyzer,
  change impact, model audit.

## Price

**Recommended initial price: US$ 19 (one-time).**

**Rationale:**

- The time saved is high. One root-cause investigation of a filter-propagation or broken-binding problem often
  takes an experienced developer 30–90 minutes. The skill produces the evidence in seconds (the synthetic
  project is analyzed in under 10 ms of engine time).
- The product is specialized and professional, but there is no comparable skill to anchor against. A low
  two-digit price lowers the barrier for individual developers and still signals a professional tool.
- It works offline with no paid APIs, so there are no running costs to pass on.
- Consider a higher team or organization tier later, once real usage and support load are known.

## Updates and support

- Versions follow semantic versioning in the `version` field of `SKILL.md`. Each new ZIP is reviewed by Agensi
  as an update, and the current version stays available during review.
- The changelog is in the README. Bug reports should include the script name, its arguments and the error
  message. Never send project files containing confidential data; synthetic reproductions are preferred.
- Planned for 1.1:
  - staged script pipeline (smaller scripts);
  - validation against real Performance Analyzer exports;
  - native Windows CI run;
  - calculation-group awareness.
