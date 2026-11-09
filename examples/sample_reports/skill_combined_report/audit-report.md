# Power BI PBIP Forensics — Audit Report

Project: **synthetic_project** · Tool powerbi-pbip-forensics 1.0.0 · Generated (UTC): 2026-11-09T02:39:50+00:00

## Executive Summary

28 findings: CRITICAL 0, HIGH 7, MEDIUM 7, LOW 7, INFO 7. Confirmed 7, potential 20, inconclusive 1.

Inventory: 1 report(s), 2 page(s), 14 visual(s), 1 model(s), 8 table(s), 21 measure(s), 7 relationship(s).

- **HIGH/confirmed** Unresolved reference [Total Cost] in '_Measures'[Margin %] (`DAX001-a6fc3f5d`)
- **HIGH/confirmed** USERELATIONSHIP references columns without a relationship in '_Measures'[Broken UseRel] (`DAX007-5f50ca7c`)
- **HIGH/confirmed** Slow visual in recorded session: Customer Accounts (`PERF001-76dd5690`)
- **HIGH/confirmed** Visual references missing measure Sales[Old Revenue]: 'Old Revenue' (card) on page 'Details' (`VIS002-77339238`)
- **HIGH/confirmed** Visual references missing column Product[Colour]: 'By Colour' (barChart) on page 'Details' (`VIS002-9448b93e`)
- **HIGH/potential** Ambiguous filter propagation between tables: Date, Product, Sales, Sales Target (`MOD006-91919a00`)
- **HIGH/potential** Unrelated tables combined in 'Customer Accounts' (tableEx) on page 'Overview': 'Account' and 'Customer' (`VIS006-94a723c2`)

## Project Inventory

| Item | Count |
|---|---|
| pbip_files | 1 |
| reports | 1 |
| pages | 2 |
| visuals | 14 |
| semantic_models | 1 |
| tables | 8 |
| columns | 28 |
| measures | 21 |
| relationships | 7 |

### Report: ContosoRetail (pbir, support: full)

Path `ContosoRetail.Report` · PBIR version 4.0 · dataset reference: ../ContosoRetail.SemanticModel

| Page | Visual | Type | Fields | Visual filters | Limitations |
|---|---|---|---|---|---|
| Overview | Total Revenue | card | 1 | 0 |  |
| Overview | Revenue by Category | clusteredColumnChart | 2 | 0 |  |
| Overview | Customer | slicer | 1 | 0 |  |
| Overview | Customer Accounts | tableEx | 3 | 0 |  |
| Overview | Bonus by Customer | tableEx | 2 | 0 |  |
| Overview | v_text | textbox | 0 | 0 |  |
| Details | Avg Spend | card | 2 | 1 |  |
| Details | By Colour | barChart | 2 | 0 |  |
| Details | Old Revenue | card | 1 | 0 |  |
| Details | Currency | slicer | 1 | 0 |  |
| Details | Flows (custom) | chordChart1A2B3C4D5E6F | 0 | 0 | Custom or unrecognized visual 'chordChart1A2B3C4D5E6F': data bindings not interpretable |
| Details | Revenue LY vs Ship Date | pivotTable | 3 | 0 |  |
| Details | Segment analysis | tableEx | 6 | 0 |  |
| Details | Target | clusteredColumnChart | 2 | 0 |  |

### Semantic model: ContosoRetail (tmdl, support: full)

| Table | Role | Columns | Measures | Calculated | Data sources |
|---|---|---|---|---|---|
| Account | fact | 4 | 1 |  | Salesforce.Data |
| Currency | disconnected | 2 | 0 |  |  |
| Customer | dimension | 3 | 0 |  | Excel.Workbook, File.Contents |
| Date | dimension | 3 | 0 | yes |  |
| Product | dimension | 3 | 0 |  |  |
| Sales Target | fact | 3 | 1 |  |  |
| Sales | fact | 10 | 3 |  | Sql.Database |
| _Measures | disconnected | 0 | 16 |  |  |

## Audit Scope

- Project folder: `synthetic_project` (read-only: True)
- Modules: diff, inspect, model_audit, perf_log, visual_deps
- Performance log: performance.json
- Skipped items (security/scope): 0

## Overall Findings

| ID | Severity | Status | Category | Title |
|---|---|---|---|---|
| DAX001-a6fc3f5d | HIGH | confirmed | DAX | Unresolved reference [Total Cost] in '_Measures'[Margin %] |
| DAX007-5f50ca7c | HIGH | confirmed | DAX | USERELATIONSHIP references columns without a relationship in '_Measures'[Broken UseRel] |
| PERF001-76dd5690 | HIGH | confirmed | Performance | Slow visual in recorded session: Customer Accounts |
| VIS002-77339238 | HIGH | confirmed | Visual dependencies | Visual references missing measure Sales[Old Revenue]: 'Old Revenue' (card) on page 'Details' |
| VIS002-9448b93e | HIGH | confirmed | Visual dependencies | Visual references missing column Product[Colour]: 'By Colour' (barChart) on page 'Details' |
| MOD006-91919a00 | HIGH | potential | Relationships | Ambiguous filter propagation between tables: Date, Product, Sales, Sales Target |
| VIS006-94a723c2 | HIGH | potential | Visual dependencies | Unrelated tables combined in 'Customer Accounts' (tableEx) on page 'Overview': 'Account' and 'Customer' |
| PERF001-98bea5b0 | MEDIUM | confirmed | Performance | Slow visual in recorded session: Revenue LY vs Ship Date |
| PERF001-fa3d6fe1 | MEDIUM | confirmed | Performance | Slow visual in recorded session: Revenue by Category |
| DAX003-97330947 | MEDIUM | potential | DAX performance | FILTER over entire table 'Sales' used as CALCULATE filter in '_Measures'[High Value Revenue] |
| DAX004-0095bb0c | MEDIUM | potential | DAX performance | Nested iterators AVERAGEX > SUMX in '_Measures'[Avg Customer Spend] |
| DAX005-df1901c4 | MEDIUM | potential | DAX performance | Context transition per row of 'Sales' in 'Sales'[Sales Per Row] |
| MOD003-3ba1a50e | MEDIUM | potential | Relationships | Bidirectional relationship: Sales <-> Product |
| MOD007-27d780fb | MEDIUM | potential | Relationships | Key data type mismatch: Sales Target[ProductKey] vs Product[ProductKey] |
| DAX008-166e0024 | LOW | potential | Filter context | Total may differ from the sum of visible rows: '_Measures'[Bonus] |
| DAX008-99bc75d5 | LOW | potential | Filter context | Total may differ from the sum of visible rows: '_Measures'[Segment Revenue] |
| DAX009-47705197 | LOW | potential | DAX | Division operator '/' with a non-constant denominator in '_Measures'[Revenue Safe] |
| DAX009-8e716128 | LOW | potential | DAX | Division operator '/' with a non-constant denominator in '_Measures'[Margin %] |
| DAX010-b753d812 | LOW | potential | DAX performance | Error-handling function in '_Measures'[Revenue Safe] |
| MOD002-5652a956 | LOW | potential | Relationships | Inactive relationship not activated by any measure: Account -> Customer |
| MOD008-c8b3d9a7 | LOW | potential | Model structure | Disconnected table not referenced by any measure: Currency |
| DAX006-78551bf8 | INFO | potential | Filter context | REMOVEFILTERS modifies filter context in '_Measures'[Revenue All Customers] |
| DAX008-e4611c35 | INFO | potential | Filter context | Total may differ from the sum of visible rows: '_Measures'[Active Customers] |
| MOD002-a665549f | INFO | potential | Relationships | Inactive relationship activated only by DAX: Sales -> Date |
| VIS004-374e99c5 | INFO | potential | Visual dependencies | Visual uses a measure flagged for performance review: [Avg Customer Spend] |
| VIS004-3c01da51 | INFO | potential | Visual dependencies | Visual uses a measure flagged for performance review: [High Value Revenue] |
| VIS004-979c2499 | INFO | potential | Visual dependencies | Visual uses a measure flagged for performance review: [Sales Per Row] |
| VIS003-4654ba20 | INFO | inconclusive | Visual dependencies | Visual not fully interpretable: 'Flows (custom)' (chordChart1A2B3C4D5E6F) on page 'Details' |

## Severity Breakdown

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 7 |
| MEDIUM | 7 |
| LOW | 7 |
| INFO | 7 |

| Status | Count |
|---|---|
| confirmed | 7 |
| potential | 20 |
| inconclusive | 1 |

## Relationship Analysis

| From | To | Active | Cross filter | Cardinality |
|---|---|---|---|---|
| 'Sales'[CustomerKey] | 'Customer'[CustomerKey] | True | oneDirection | many:one |
| 'Sales'[ProductKey] | 'Product'[ProductKey] | True | bothDirections | many:one |
| 'Sales'[OrderDate] | 'Date'[Date] | True | oneDirection | many:one |
| 'Sales'[ShipDate] | 'Date'[Date] | False | oneDirection | many:one |
| 'Sales Target'[ProductKey] | 'Product'[ProductKey] | True | oneDirection | many:one |
| 'Sales Target'[TargetDate] | 'Date'[Date] | True | oneDirection | many:one |
| 'Account'[CustomerKey] | 'Customer'[CustomerKey] | False | oneDirection | many:one |

| ID | Severity | Status | Category | Title |
|---|---|---|---|---|
| MOD006-91919a00 | HIGH | potential | Relationships | Ambiguous filter propagation between tables: Date, Product, Sales, Sales Target |
| MOD003-3ba1a50e | MEDIUM | potential | Relationships | Bidirectional relationship: Sales <-> Product |
| MOD007-27d780fb | MEDIUM | potential | Relationships | Key data type mismatch: Sales Target[ProductKey] vs Product[ProductKey] |
| MOD002-5652a956 | LOW | potential | Relationships | Inactive relationship not activated by any measure: Account -> Customer |
| MOD008-c8b3d9a7 | LOW | potential | Model structure | Disconnected table not referenced by any measure: Currency |
| MOD002-a665549f | INFO | potential | Relationships | Inactive relationship activated only by DAX: Sales -> Date |

## DAX Analysis

| ID | Severity | Status | Category | Title |
|---|---|---|---|---|
| DAX001-a6fc3f5d | HIGH | confirmed | DAX | Unresolved reference [Total Cost] in '_Measures'[Margin %] |
| DAX007-5f50ca7c | HIGH | confirmed | DAX | USERELATIONSHIP references columns without a relationship in '_Measures'[Broken UseRel] |
| DAX003-97330947 | MEDIUM | potential | DAX performance | FILTER over entire table 'Sales' used as CALCULATE filter in '_Measures'[High Value Revenue] |
| DAX004-0095bb0c | MEDIUM | potential | DAX performance | Nested iterators AVERAGEX > SUMX in '_Measures'[Avg Customer Spend] |
| DAX005-df1901c4 | MEDIUM | potential | DAX performance | Context transition per row of 'Sales' in 'Sales'[Sales Per Row] |
| DAX008-166e0024 | LOW | potential | Filter context | Total may differ from the sum of visible rows: '_Measures'[Bonus] |
| DAX008-99bc75d5 | LOW | potential | Filter context | Total may differ from the sum of visible rows: '_Measures'[Segment Revenue] |
| DAX009-47705197 | LOW | potential | DAX | Division operator '/' with a non-constant denominator in '_Measures'[Revenue Safe] |
| DAX009-8e716128 | LOW | potential | DAX | Division operator '/' with a non-constant denominator in '_Measures'[Margin %] |
| DAX010-b753d812 | LOW | potential | DAX performance | Error-handling function in '_Measures'[Revenue Safe] |
| DAX006-78551bf8 | INFO | potential | Filter context | REMOVEFILTERS modifies filter context in '_Measures'[Revenue All Customers] |
| DAX008-e4611c35 | INFO | potential | Filter context | Total may differ from the sum of visible rows: '_Measures'[Active Customers] |

| Measure | Depth | Depends on |
|---|---|---|
| [Revenue % of All Customers] | 3 | Revenue All Customers, Total Revenue |
| [Sales Per Row] | 2 | Total Revenue |
| [Revenue LY] | 2 | Total Revenue |
| [Revenue All Customers] | 2 | Total Revenue |
| [High Value Revenue] | 2 | Total Revenue |
| [Margin %] | 2 | Total Revenue |
| [Revenue by Ship Date] | 2 | Total Revenue |
| [Broken UseRel] | 2 | Total Revenue |
| [Bonus] | 2 | Total Revenue |
| [Segment Revenue] | 2 | Total Revenue |
| [Revenue (R$) – Net] | 2 | Total Revenue |
| [Customer's Rank] | 2 | Total Revenue |
| [Revenue Safe] | 2 | Total Quantity, Total Revenue |
| [Formatted Label] | 2 | Total Revenue |
| [Total Balance] | 1 |  |

## Visual Dependencies

| ID | Severity | Status | Category | Title |
|---|---|---|---|---|
| VIS002-77339238 | HIGH | confirmed | Visual dependencies | Visual references missing measure Sales[Old Revenue]: 'Old Revenue' (card) on page 'Details' |
| VIS002-9448b93e | HIGH | confirmed | Visual dependencies | Visual references missing column Product[Colour]: 'By Colour' (barChart) on page 'Details' |
| VIS006-94a723c2 | HIGH | potential | Visual dependencies | Unrelated tables combined in 'Customer Accounts' (tableEx) on page 'Overview': 'Account' and 'Customer' |
| VIS004-374e99c5 | INFO | potential | Visual dependencies | Visual uses a measure flagged for performance review: [Avg Customer Spend] |
| VIS004-3c01da51 | INFO | potential | Visual dependencies | Visual uses a measure flagged for performance review: [High Value Revenue] |
| VIS004-979c2499 | INFO | potential | Visual dependencies | Visual uses a measure flagged for performance review: [Sales Per Row] |
| VIS003-4654ba20 | INFO | inconclusive | Visual dependencies | Visual not fully interpretable: 'Flows (custom)' (chordChart1A2B3C4D5E6F) on page 'Details' |

Dependency map: 26 bindings (Page → Visual → Field → Table).

| Page | Visual | Usage | Kind | Table | Field | Status |
|---|---|---|---|---|---|---|
| Overview | Total Revenue | projection | measure | Sales | Total Revenue | ok |
| Overview | Revenue by Category | projection | column | Product | Category | ok |
| Overview | Revenue by Category | projection | measure | Sales | Total Revenue | ok |
| Overview | Customer | projection | column | Customer | Customer Name | ok |
| Overview | Customer Accounts | projection | column | Customer | Customer Name | ok |
| Overview | Customer Accounts | projection | column | Account | Account Name | ok |
| Overview | Customer Accounts | projection | aggregation | Account | Balance | ok |
| Overview | Bonus by Customer | projection | column | Customer | Customer Name | ok |
| Overview | Bonus by Customer | projection | measure | _Measures | Bonus | ok |
| Details | Avg Spend | projection | measure | _Measures | Avg Customer Spend | ok |
| Details | Avg Spend | filter | column | Product | Category | ok |
| Details | By Colour | projection | column | Product | Colour | missing-field |
| Details | By Colour | projection | measure | Sales | Total Revenue | ok |
| Details | Old Revenue | projection | measure | Sales | Old Revenue | missing-field |
| Details | Currency | projection | column | Currency | Code | ok |
| Details | Revenue LY vs Ship Date | projection | column | Date | Year | ok |
| Details | Revenue LY vs Ship Date | projection | measure | _Measures | Revenue LY | ok |
| Details | Revenue LY vs Ship Date | projection | measure | _Measures | Revenue by Ship Date | ok |
| Details | Segment analysis | projection | column | Customer | Segment | ok |
| Details | Segment analysis | projection | measure | _Measures | Revenue % of All Customers | ok |
| Details | Segment analysis | projection | measure | _Measures | Segment Revenue | ok |
| Details | Segment analysis | projection | measure | _Measures | Margin % | ok |
| Details | Segment analysis | projection | measure | _Measures | High Value Revenue | ok |
| Details | Segment analysis | projection | measure | Sales | Sales Per Row | ok |
| Details | Target | projection | column | Date | Year | ok |
| Details | Target | projection | measure | Sales Target | Target Amount | ok |

## Performance Analysis

Log version 1.1.0, 21 events, 5 visual lifecycles (sorted by measured total).

| Visual | Type | Total ms | DAX ms | DirectQuery ms | Display ms | Other ms |
|---|---|---|---|---|---|---|
| Customer Accounts | tableEx | 3420.0 | 3198.0 | 0.0 | 180.0 | 42.0 |
| Revenue by Category | clusteredColumnChart | 1500.0 | 218.0 | 0.0 | 1250.0 | 32.0 |
| Revenue LY vs Ship Date | pivotTable | 1320.0 | 298.0 | 0.0 | 120.0 | 902.0 |
| Total Revenue | card | 120.0 | 78.0 | 0.0 | 30.0 | 12.0 |
| Legacy KPI | kpi | 75.0 | 48.0 | 0.0 | 20.0 | 7.0 |

| ID | Severity | Status | Category | Title |
|---|---|---|---|---|
| PERF001-76dd5690 | HIGH | confirmed | Performance | Slow visual in recorded session: Customer Accounts |
| PERF001-98bea5b0 | MEDIUM | confirmed | Performance | Slow visual in recorded session: Revenue LY vs Ship Date |
| PERF001-fa3d6fe1 | MEDIUM | confirmed | Performance | Slow visual in recorded session: Revenue by Category |

## Change Impact

Summary: added 1, removed 3, modified 2, modified-formatting 1. Textual/structural changes indicate where to test; they are not proof of a functional regression.

| Type | Object | Change | Details |
|---|---|---|---|
| measure | Bonus | removed |  |
| measure | Unused Helper | removed |  |
| column | 'Product'[Colour] | added |  |
| measure | Total Quantity | modified-formatting | Whitespace/comment-only change; tokens identical |
| measure | Total Revenue | modified | DAX expression changed (token-level) |
| relationship | 'Account'[CustomerKey] -> 'Customer'[CustomerKey] | modified | isActive: False -> True |
| visual | ContosoRetail/details01/v_target | removed |  |

### measure Bonus (removed)

Measure 'Bonus' was removed. It is still referenced by visuals in the current version: these bindings are broken (confirmed).

- Visual: ContosoRetail / Overview / Bonus by Customer (tableEx)

### measure Unused Helper (removed)

Measure 'Unused Helper' was removed. No visual in the current version references it.

- No dependents found.

### measure Total Revenue (modified)

Measure 'Total Revenue' modified. Visuals referencing it (directly or via dependent measures) may require regression testing.

- Dependent measure: Broken UseRel
- Dependent measure: Customer's Rank
- Dependent measure: Formatted Label
- Dependent measure: High Value Revenue
- Dependent measure: Margin %
- Dependent measure: Revenue % of All Customers
- Dependent measure: Revenue (R$) – Net
- Dependent measure: Revenue All Customers
- Dependent measure: Revenue by Ship Date
- Dependent measure: Revenue LY
- Dependent measure: Revenue Safe
- Dependent measure: Sales Per Row
- Dependent measure: Segment Revenue
- Visual: ContosoRetail / Details / By Colour (barChart)
- Visual: ContosoRetail / Details / Revenue LY vs Ship Date (pivotTable)
- Visual: ContosoRetail / Details / Segment analysis (tableEx)
- Visual: ContosoRetail / Overview / Revenue by Category (clusteredColumnChart)
- Visual: ContosoRetail / Overview / Total Revenue (card)

### relationship 'Account'[CustomerKey] -> 'Customer'[CustomerKey] (modified)

Relationship change alters filter propagation between account, customer. Measures aggregating these tables and visuals using them may require regression testing.

- Dependent measure: Avg Customer Spend
- Dependent measure: Segment Revenue
- Dependent measure: Total Balance
- Visual: ContosoRetail / Details / Avg Spend (card)
- Visual: ContosoRetail / Details / Segment analysis (tableEx)
- Visual: ContosoRetail / Overview / Bonus by Customer (tableEx)
- Visual: ContosoRetail / Overview / Customer (slicer)
- Visual: ContosoRetail / Overview / Customer Accounts (tableEx)

## Root Cause Hypotheses

### Investigation: Customer → Account

Deterministic evidence:

```text
Direction-compatible active paths 'Customer' -> 'Account': 0
  BLOCKED PATH: 'Customer' -> 'Account' via 'Account'[CustomerKey] (many) -> 'Customer'[CustomerKey] (one) [INACTIVE]
Visual 'Customer Accounts' (tableEx) has 0 visual-level filter(s): 
```

**#1 [high confidence]** Inactive relationship on the only path from 'Customer' to 'Account': 'Account'[CustomerKey] (many) -> 'Customer'[CustomerKey] (one). — Structural evidence: the relationship has isActive=false and no other active path exists.

- Confirm isActive=false in Model view.
- Create a test measure: CALCULATE([<measure>], USERELATIONSHIP('Account'[CustomerKey], 'Customer'[CustomerKey])) and compare.
- Decide whether to activate the relationship or use the USERELATIONSHIP measure in visuals.

## Recommended Actions

1. [HIGH] DAX001: Fix the reference (renamed/removed object) or restore the missing object.
2. [HIGH] DAX007: Reference the columns of an existing relationship.
3. [HIGH] PERF001: DAX query time dominates: copy the query (Copy query) into DAX query view or DAX Studio, check server timings and review the measures involved.
4. [HIGH] VIS002: Rebind the visual to an existing field or restore the renamed/removed object.
5. [HIGH] MOD006: Make one relationship inactive or single-direction so only one path remains.
6. [HIGH] VIS006: Activate/create the relationship path or add a measure that defines the link.
7. [MEDIUM] PERF001: 'Other' dominates: the visual waited for other operations (queueing on the UI thread); reduce the number of visuals on the page or use bookmarks/drill-through.
8. [MEDIUM] PERF001: Visual display dominates: reduce data points/rows, simplify formatting or custom visual rendering.
9. [MEDIUM] DAX003: Use column predicates (e.g., 'T'[Col] > x) or FILTER(VALUES('T'[Col]), ...); add KEEPFILTERS if the intent is to intersect with existing filters.
10. [MEDIUM] DAX004: Pre-aggregate (SUMMARIZE/ADDCOLUMNS with a measure) or move logic to a column if static.
11. [MEDIUM] DAX005: Iterate a dimension or VALUES of a key column instead of the fact table.
12. [MEDIUM] MOD003: Prefer single direction; use CROSSFILTER(..., BOTH) inside specific measures if required.
13. [MEDIUM] MOD007: Align the data types in Power Query.

## Limitations

- Textual/structural changes indicate where to test; they are not proof of a functional regression.
- Inventory only; run the audit scripts for diagnostics.
- Static analysis only: DAX is not executed and no data values are read.
- Filter-propagation results are derived from relationship metadata, not from query plans.
- Durations come only from the provided log; 'Other' is derived and includes queueing.
- Unused-measure detection skipped for model 'ContosoRetail': reports not fully interpretable (ContosoRetail)

## Evidence Appendix

### DAX001-a6fc3f5d — Unresolved reference [Total Cost] in '_Measures'[Margin %]

- Severity: HIGH · Status: confirmed · Category: DAX
- Source: `ContosoRetail.SemanticModel/definition/tables/_Measures.tmdl:20` · Object: `ContosoRetail/measure/_Measures/Margin %/[Total Cost]`
- Explanation: The referenced object is not defined in the parsed semantic model.
- Impact: The expression fails to evaluate; every visual using it shows an error.
- Recommendation: Fix the reference (renamed/removed object) or restore the missing object.
- Verification: Open the expression in Power BI Desktop; invalid references are underlined.

```text
Expression references [Total Cost]
no measure or column with this name in the model
```

### DAX007-5f50ca7c — USERELATIONSHIP references columns without a relationship in '_Measures'[Broken UseRel]

- Severity: HIGH · Status: confirmed · Category: DAX
- Source: `ContosoRetail.SemanticModel/definition/tables/_Measures.tmdl:24` · Object: `ContosoRetail/measure/_Measures/Broken UseRel/USERELATIONSHIP`
- Explanation: USERELATIONSHIP requires an existing relationship.
- Impact: The measure returns an error.
- Recommendation: Reference the columns of an existing relationship.
- Verification: Evaluate the measure in Power BI Desktop.

```text
USERELATIONSHIP('Sales'[ProductKey], 'Customer'[CustomerKey])
No relationship between these columns exists in the model
```

### PERF001-76dd5690 — Slow visual in recorded session: Customer Accounts

- Severity: HIGH · Status: confirmed · Category: Performance
- Source: `performance.json` · Object: `perf/v_table_accounts/2026-10-01T12:00:01.000Z`
- Explanation: Duration measured by Performance Analyzer during the recorded session.
- Impact: Users experience delay on this visual; durations include queueing on the UI thread.
- Recommendation: DAX query time dominates: copy the query (Copy query) into DAX query view or DAX Studio, check server timings and review the measures involved.
- Verification: Record a new session with Performance Analyzer (clear cache by refreshing visuals) and compare.

```text
Measured total: 3420.0 ms (threshold 1000/3000 ms)
DAX query: 3198.0 ms; Direct query: 0.0 ms; Visual display: 180.0 ms; Other (derived): 42.0 ms
```

### VIS002-77339238 — Visual references missing measure Sales[Old Revenue]: 'Old Revenue' (card) on page 'Details'

- Severity: HIGH · Status: confirmed · Category: Visual dependencies
- Source: `ContosoRetail.Report/definition/pages/details01/visuals/v_broken_measure/visual.json` · Object: `ContosoRetail/details01/v_broken_measure/Sales[Old Revenue]`
- Explanation: The visual binds a field that does not exist in the semantic model it is connected to.
- Impact: The visual shows an error ('Something's wrong with one or more fields').
- Recommendation: Rebind the visual to an existing field or restore the renamed/removed object.
- Verification: Open the page in Power BI Desktop and check the visual for a field error.

```text
projection field Sales[Old Revenue] (role 'Values')
measure 'Old Revenue' not found in 'Sales'
```

### VIS002-9448b93e — Visual references missing column Product[Colour]: 'By Colour' (barChart) on page 'Details'

- Severity: HIGH · Status: confirmed · Category: Visual dependencies
- Source: `ContosoRetail.Report/definition/pages/details01/visuals/v_broken_column/visual.json` · Object: `ContosoRetail/details01/v_broken_column/Product[Colour]`
- Explanation: The visual binds a field that does not exist in the semantic model it is connected to.
- Impact: The visual shows an error ('Something's wrong with one or more fields').
- Recommendation: Rebind the visual to an existing field or restore the renamed/removed object.
- Verification: Open the page in Power BI Desktop and check the visual for a field error.

```text
projection field Product[Colour] (role 'Category')
column 'Colour' not found in 'Product'
```

### MOD006-91919a00 — Ambiguous filter propagation between tables: Date, Product, Sales, Sales Target

- Severity: HIGH · Status: potential · Category: Relationships
- Source: `ContosoRetail.SemanticModel/definition/relationships.tmdl:19` · Object: `ContosoRetail/cycle/6c0d2f01-0000-4000-8000-000000000002+6c0d2f01-0000-4000-8000-000000000003+6c0d2f01-0000-4000-8000-000000000005+6c0d2f01-0000-4000-8000-000000000006`
- Explanation: More than one active, direction-compatible path connects the same tables.
- Impact: Filter results depend on which path the engine uses; Power BI may also refuse to activate one of the relationships.
- Recommendation: Make one relationship inactive or single-direction so only one path remains.
- Verification: Open Model view in Power BI Desktop and check for ambiguity warnings; test the affected measures.

```text
'Sales Target'[ProductKey] (many) -> 'Product'[ProductKey] (one)
'Sales Target'[TargetDate] (many) -> 'Date'[Date] (one)
'Sales'[OrderDate] (many) -> 'Date'[Date] (one)
'Sales'[ProductKey] (many) <-> 'Product'[ProductKey] (one)
'Date' reaches 'Sales Target' through 2 active paths: Date -> Sales Target | Date -> Sales -> Product -> Sales Target
```

### VIS006-94a723c2 — Unrelated tables combined in 'Customer Accounts' (tableEx) on page 'Overview': 'Account' and 'Customer'

- Severity: HIGH · Status: potential · Category: Visual dependencies
- Source: `ContosoRetail.Report/definition/pages/overview01/visuals/v_table_accounts/visual.json` · Object: `ContosoRetail/overview01/v_table_accounts/Account+Customer`
- Explanation: Power BI cannot use relationships to restrict combinations of these columns.
- Impact: The visual may list rows that look unrelated (e.g., all accounts for each customer) or show a relationship error.
- Recommendation: Activate/create the relationship path or add a measure that defines the link.
- Verification: Run: pbip-forensics investigate --from-table "Account" --to-table "Customer".

```text
Columns from 'Account' and 'Customer' in the same tableEx
No active relationship path between them in either direction
```

### PERF001-98bea5b0 — Slow visual in recorded session: Revenue LY vs Ship Date

- Severity: MEDIUM · Status: confirmed · Category: Performance
- Source: `performance.json` · Object: `perf/v_matrix_ly/2026-10-01T12:00:01.000Z`
- Explanation: Duration measured by Performance Analyzer during the recorded session.
- Impact: Users experience delay on this visual; durations include queueing on the UI thread.
- Recommendation: 'Other' dominates: the visual waited for other operations (queueing on the UI thread); reduce the number of visuals on the page or use bookmarks/drill-through.
- Verification: Record a new session with Performance Analyzer (clear cache by refreshing visuals) and compare.

```text
Measured total: 1320.0 ms (threshold 1000/3000 ms)
DAX query: 298.0 ms; Direct query: 0.0 ms; Visual display: 120.0 ms; Other (derived): 902.0 ms
```

### PERF001-fa3d6fe1 — Slow visual in recorded session: Revenue by Category

- Severity: MEDIUM · Status: confirmed · Category: Performance
- Source: `performance.json` · Object: `perf/v_col_category/2026-10-01T12:00:01.000Z`
- Explanation: Duration measured by Performance Analyzer during the recorded session.
- Impact: Users experience delay on this visual; durations include queueing on the UI thread.
- Recommendation: Visual display dominates: reduce data points/rows, simplify formatting or custom visual rendering.
- Verification: Record a new session with Performance Analyzer (clear cache by refreshing visuals) and compare.

```text
Measured total: 1500.0 ms (threshold 1000/3000 ms)
DAX query: 218.0 ms; Direct query: 0.0 ms; Visual display: 1250.0 ms; Other (derived): 32.0 ms
```

### DAX003-97330947 — FILTER over entire table 'Sales' used as CALCULATE filter in '_Measures'[High Value Revenue]

- Severity: MEDIUM · Status: potential · Category: DAX performance
- Source: `ContosoRetail.SemanticModel/definition/tables/_Measures.tmdl:14` · Object: `ContosoRetail/measure/_Measures/High Value Revenue/filter-1`
- Explanation: A table filter iterates every row of the (expanded) table and keeps all its columns as filter.
- Impact: Often slower than a column predicate and may filter related tables more than intended.
- Recommendation: Use column predicates (e.g., 'T'[Col] > x) or FILTER(VALUES('T'[Col]), ...); add KEEPFILTERS if the intent is to intersect with existing filters.
- Verification: Compare query duration (Performance Analyzer / DAX query view) before and after the change.

```text
CALCULATE( ..., FILTER(Sales, ...) ) at expression line 4
'Sales' structural role: fact
```

### DAX004-0095bb0c — Nested iterators AVERAGEX > SUMX in '_Measures'[Avg Customer Spend]

- Severity: MEDIUM · Status: potential · Category: DAX performance
- Source: `ContosoRetail.SemanticModel/definition/tables/_Measures.tmdl:18` · Object: `ContosoRetail/measure/_Measures/Avg Customer Spend/nested-1`
- Explanation: The inner iteration runs once per row of the outer iteration.
- Impact: Cost grows with the product of both cardinalities; risk depends on data volume.
- Recommendation: Pre-aggregate (SUMMARIZE/ADDCOLUMNS with a measure) or move logic to a column if static.
- Verification: Measure server timings in DAX query view or DAX Studio with realistic filters.

```text
SUMX is evaluated inside the row expression of AVERAGEX
outer table: Customer
inner table: (expression)
```

### DAX005-df1901c4 — Context transition per row of 'Sales' in 'Sales'[Sales Per Row]

- Severity: MEDIUM · Status: potential · Category: DAX performance
- Source: `ContosoRetail.SemanticModel/definition/tables/Sales.tmdl:12` · Object: `ContosoRetail/measure/Sales/Sales Per Row/ctx-0`
- Explanation: Referencing a measure inside an iterator triggers context transition for every row.
- Impact: On large fact tables this can be expensive and may duplicate rows with identical values.
- Recommendation: Iterate a dimension or VALUES of a key column instead of the fact table.
- Verification: Compare duration and results with the alternative formulation.

```text
SUMX(Sales, ...) evaluates [Total Revenue] per row
'Sales' structural role: fact
```

### MOD003-3ba1a50e — Bidirectional relationship: Sales <-> Product

- Severity: MEDIUM · Status: potential · Category: Relationships
- Source: `ContosoRetail.SemanticModel/definition/relationships.tmdl:5` · Object: `ContosoRetail/relationship/6c0d2f01-0000-4000-8000-000000000002`
- Explanation: Bidirectional cross-filtering lets the many side filter the one side, which can create additional filter paths.
- Impact: Possible ambiguity, unexpected filtering of dimensions and slower queries.
- Recommendation: Prefer single direction; use CROSSFILTER(..., BOTH) inside specific measures if required.
- Verification: Check whether slicers on related dimensions change unexpectedly when this table is filtered.

```text
'Sales'[ProductKey] (many) <-> 'Product'[ProductKey] (one)
crossFilteringBehavior: bothDirections
'Sales' is fact, 'Product' is dimension
```

### MOD007-27d780fb — Key data type mismatch: Sales Target[ProductKey] vs Product[ProductKey]

- Severity: MEDIUM · Status: potential · Category: Relationships
- Source: `ContosoRetail.SemanticModel/definition/relationships.tmdl:19` · Object: `ContosoRetail/relationship/6c0d2f01-0000-4000-8000-000000000005`
- Explanation: Relationship key columns have different declared data types.
- Impact: Implicit conversion can cause unmatched keys (blank member) and slower joins.
- Recommendation: Align the data types in Power Query.
- Verification: Look for a (Blank) member when slicing by the one-side table.

```text
'Sales Target'[ProductKey] (many) -> 'Product'[ProductKey] (one)
string vs int64
```

### DAX008-166e0024 — Total may differ from the sum of visible rows: '_Measures'[Bonus]

- Severity: LOW · Status: potential · Category: Filter context
- Source: `ContosoRetail.SemanticModel/definition/tables/_Measures.tmdl:26` · Object: `ContosoRetail/measure/_Measures/Bonus/totals`
- Explanation: Power BI evaluates the measure again in the total's filter context; it does not sum the rows.
- Impact: Users may perceive totals as wrong.
- Recommendation: If the total must be the sum of rows, iterate the grouping column (SUMX(VALUES(...), [Measure])).
- Verification: Export the visible rows, sum them, and compare with the total for the same filters.

```text
IF/SWITCH evaluated on measure values without iterating rows: at the total level the condition is evaluated once on the aggregate
```

### DAX008-99bc75d5 — Total may differ from the sum of visible rows: '_Measures'[Segment Revenue]

- Severity: LOW · Status: potential · Category: Filter context
- Source: `ContosoRetail.SemanticModel/definition/tables/_Measures.tmdl:30` · Object: `ContosoRetail/measure/_Measures/Segment Revenue/totals`
- Explanation: Power BI evaluates the measure again in the total's filter context; it does not sum the rows.
- Impact: Users may perceive totals as wrong.
- Recommendation: If the total must be the sum of rows, iterate the grouping column (SUMX(VALUES(...), [Measure])).
- Verification: Export the visible rows, sum them, and compare with the total for the same filters.

```text
IF/SWITCH evaluated on measure values without iterating rows: at the total level the condition is evaluated once on the aggregate
uses HASONEVALUE, SELECTEDVALUE: total rows follow a different branch by design
```

### DAX009-47705197 — Division operator '/' with a non-constant denominator in '_Measures'[Revenue Safe]

- Severity: LOW · Status: potential · Category: DAX
- Source: `ContosoRetail.SemanticModel/definition/tables/_Measures.tmdl:39` · Object: `ContosoRetail/measure/_Measures/Revenue Safe/divide`
- Explanation: The '/' operator raises an error/infinity when the denominator is zero or blank.
- Impact: Visuals may show errors or Infinity for some selections.
- Recommendation: Use DIVIDE(numerator, denominator) to handle zero denominators.
- Verification: Select a slice where the denominator is zero or blank.

```text
'/' at expression line 1
```

### DAX009-8e716128 — Division operator '/' with a non-constant denominator in '_Measures'[Margin %]

- Severity: LOW · Status: potential · Category: DAX
- Source: `ContosoRetail.SemanticModel/definition/tables/_Measures.tmdl:20` · Object: `ContosoRetail/measure/_Measures/Margin %/divide`
- Explanation: The '/' operator raises an error/infinity when the denominator is zero or blank.
- Impact: Visuals may show errors or Infinity for some selections.
- Recommendation: Use DIVIDE(numerator, denominator) to handle zero denominators.
- Verification: Select a slice where the denominator is zero or blank.

```text
'/' at expression line 1
```

### DAX010-b753d812 — Error-handling function in '_Measures'[Revenue Safe]

- Severity: LOW · Status: potential · Category: DAX performance
- Source: `ContosoRetail.SemanticModel/definition/tables/_Measures.tmdl:39` · Object: `ContosoRetail/measure/_Measures/Revenue Safe/iferror`
- Explanation: IFERROR/ISERROR can force slower evaluation and hide data problems.
- Impact: Possible performance cost; masked errors.
- Recommendation: Prefer DIVIDE or explicit checks.
- Verification: Compare query durations with and without the error handler.

```text
uses IFERROR
```

### MOD002-5652a956 — Inactive relationship not activated by any measure: Account -> Customer

- Severity: LOW · Status: potential · Category: Relationships
- Source: `ContosoRetail.SemanticModel/definition/relationships.tmdl:27` · Object: `ContosoRetail/relationship/6c0d2f01-0000-4000-8000-000000000007`
- Explanation: This relationship does not propagate filters and no measure in the model activates it.
- Impact: Selections on 'Customer' will not filter 'Account' through this relationship; visuals may show unrelated rows or repeated totals.
- Recommendation: Activate it, remove it, or add measures that use USERELATIONSHIP where needed.
- Verification: Place a column of 'Customer' and a column/measure of 'Account' in a table visual and observe whether rows are restricted.

```text
'Account'[CustomerKey] (many) -> 'Customer'[CustomerKey] (one)
isActive: false
No USERELATIONSHIP reference found in any measure
```

### MOD008-c8b3d9a7 — Disconnected table not referenced by any measure: Currency

- Severity: LOW · Status: potential · Category: Model structure
- Source: `ContosoRetail.SemanticModel/definition/tables/Currency.tmdl:1` · Object: `ContosoRetail/table/Currency`
- Explanation: Filters on this table cannot propagate to any other table.
- Impact: Slicers or visuals combining this table with other tables will not filter them.
- Recommendation: Create the missing relationship or remove the table if unused.
- Verification: Add a slicer from this table next to a measure from a fact table and check if values change.

```text
Table 'Currency' has no relationships
No measure references its columns
```

### DAX006-78551bf8 — REMOVEFILTERS modifies filter context in '_Measures'[Revenue All Customers]

- Severity: INFO · Status: potential · Category: Filter context
- Source: `ContosoRetail.SemanticModel/definition/tables/_Measures.tmdl:5` · Object: `ContosoRetail/measure/_Measures/Revenue All Customers/REMOVEFILTERS-'Customer'`
- Explanation: REMOVEFILTERS removes (or restores) filters on 'Customer' for this calculation.
- Impact: Selections on those objects do not restrict this measure; this is a common cause of 'measure ignores my slicer'.
- Recommendation: Confirm the intent; use KEEPFILTERS or narrower column targets if selections must apply.
- Verification: Apply a slicer on the target and compare this measure with its base measure.

```text
REMOVEFILTERS('Customer') used as calculate-filter
```

### DAX008-e4611c35 — Total may differ from the sum of visible rows: '_Measures'[Active Customers]

- Severity: INFO · Status: potential · Category: Filter context
- Source: `ContosoRetail.SemanticModel/definition/tables/_Measures.tmdl:28` · Object: `ContosoRetail/measure/_Measures/Active Customers/totals`
- Explanation: Power BI evaluates the measure again in the total's filter context; it does not sum the rows.
- Impact: Users may perceive totals as wrong.
- Recommendation: If the total must be the sum of rows, iterate the grouping column (SUMX(VALUES(...), [Measure])).
- Verification: Export the visible rows, sum them, and compare with the total for the same filters.

```text
DISTINCTCOUNT is non-additive: the total is not the sum of rows
```

### MOD002-a665549f — Inactive relationship activated only by DAX: Sales -> Date

- Severity: INFO · Status: potential · Category: Relationships
- Source: `ContosoRetail.SemanticModel/definition/relationships.tmdl:14` · Object: `ContosoRetail/relationship/6c0d2f01-0000-4000-8000-000000000004`
- Explanation: Inactive relationships never propagate filters unless a measure activates them.
- Impact: Only the listed measures respond to filters through this path; all other measures ignore it.
- Recommendation: Confirm this is intentional (e.g., role-playing date) and document the activating measures.
- Verification: In a table visual, compare a listed measure against a non-activating measure for the same selection.

```text
'Sales'[ShipDate] (many) -> 'Date'[Date] (one)
isActive: false
Activated via USERELATIONSHIP in: Revenue by Ship Date
```

### VIS004-374e99c5 — Visual uses a measure flagged for performance review: [Avg Customer Spend]

- Severity: INFO · Status: potential · Category: Visual dependencies
- Source: `ContosoRetail.Report/definition/pages/details01/visuals/v_avg_spend/visual.json` · Object: `ContosoRetail/details01/v_avg_spend/Avg Customer Spend`
- Explanation: The measure has DAX patterns flagged by DAX003/DAX004/DAX005.
- Impact: Static risk only; real impact must be measured.
- Recommendation: Prioritize this visual when profiling with Performance Analyzer.
- Verification: Record a Performance Analyzer session and check this visual's DAX query time.

```text
'Avg Spend' (card) on page 'Details' uses [Avg Customer Spend]
dependency depth: 1
```

### VIS004-3c01da51 — Visual uses a measure flagged for performance review: [High Value Revenue]

- Severity: INFO · Status: potential · Category: Visual dependencies
- Source: `ContosoRetail.Report/definition/pages/details01/visuals/v_pct/visual.json` · Object: `ContosoRetail/details01/v_pct/High Value Revenue`
- Explanation: The measure has DAX patterns flagged by DAX003/DAX004/DAX005.
- Impact: Static risk only; real impact must be measured.
- Recommendation: Prioritize this visual when profiling with Performance Analyzer.
- Verification: Record a Performance Analyzer session and check this visual's DAX query time.

```text
'Segment analysis' (tableEx) on page 'Details' uses [High Value Revenue]
dependency depth: 2
```

### VIS004-979c2499 — Visual uses a measure flagged for performance review: [Sales Per Row]

- Severity: INFO · Status: potential · Category: Visual dependencies
- Source: `ContosoRetail.Report/definition/pages/details01/visuals/v_pct/visual.json` · Object: `ContosoRetail/details01/v_pct/Sales Per Row`
- Explanation: The measure has DAX patterns flagged by DAX003/DAX004/DAX005.
- Impact: Static risk only; real impact must be measured.
- Recommendation: Prioritize this visual when profiling with Performance Analyzer.
- Verification: Record a Performance Analyzer session and check this visual's DAX query time.

```text
'Segment analysis' (tableEx) on page 'Details' uses [Sales Per Row]
dependency depth: 2
```

### VIS003-4654ba20 — Visual not fully interpretable: 'Flows (custom)' (chordChart1A2B3C4D5E6F) on page 'Details'

- Severity: INFO · Status: inconclusive · Category: Visual dependencies
- Source: `ContosoRetail.Report/definition/pages/details01/visuals/v_custom/visual.json` · Object: `ContosoRetail/details01/v_custom`
- Explanation: The visual definition uses constructs this version cannot interpret.
- Impact: Dependencies of this visual may be incomplete in this audit.
- Recommendation: Review this visual manually in Power BI Desktop.
- Verification: Open the visual's field wells and filters pane.

```text
Custom or unrecognized visual 'chordChart1A2B3C4D5E6F': data bindings not interpretable
```
