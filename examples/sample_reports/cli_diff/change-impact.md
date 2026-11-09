# Power BI PBIP Forensics — Audit Report

Project: **synthetic_project -> synthetic_project_v2** · Tool powerbi-pbip-forensics 1.0.0 · Generated (UTC): 

## Executive Summary

0 findings produced by this command (full rule set runs with `audit`).

Inventory: 0 report(s), 0 page(s), 0 visual(s), 0 model(s), 0 table(s), 0 measure(s), 0 relationship(s).

## Project Inventory

_(empty)_

## Audit Scope

- Project folder: `synthetic_project -> synthetic_project_v2` (read-only: True)
- Modules: change-impact
- Performance log: not provided
- Skipped items (security/scope): 0

## Overall Findings

No findings in this section.

## Severity Breakdown

_(empty)_

_(empty)_

## Relationship Analysis

No findings in this section.

## DAX Analysis

No findings in this section.

## Visual Dependencies

No findings in this section.

Dependency map: 0 bindings (Page → Visual → Field → Table).

_(empty)_

## Performance Analysis

No Performance Analyzer log was provided. No runtime measurements are available; the items below are static risks that should be measured before acting.

No findings in this section.

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
- Dependent measure: Total Balance
- Visual: ContosoRetail / Details / Avg Spend (card)
- Visual: ContosoRetail / Details / Segment analysis (tableEx)
- Visual: ContosoRetail / Overview / Bonus by Customer (tableEx)
- Visual: ContosoRetail / Overview / Customer (slicer)
- Visual: ContosoRetail / Overview / Customer Accounts (tableEx)

## Root Cause Hypotheses

No investigation was requested. Use the `investigate` command for question-driven analysis.

## Recommended Actions

No findings in this section.

## Limitations


## Evidence Appendix
