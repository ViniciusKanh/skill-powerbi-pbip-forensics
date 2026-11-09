# Power BI PBIP Forensics — Audit Report

Project: **synthetic_project** · Tool powerbi-pbip-forensics 1.0.0 · Generated (UTC): 

## Executive Summary

0 findings produced by this command (full rule set runs with `audit`).

Inventory: 0 report(s), 0 page(s), 0 visual(s), 0 model(s), 0 table(s), 0 measure(s), 0 relationship(s).

## Project Inventory

_(empty)_

## Audit Scope

- Project folder: `synthetic_project` (read-only: True)
- Modules: filter-investigation
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

No version comparison was requested for this report.

## Root Cause Hypotheses

### Investigation: Customer → Sales (measure Revenue All Customers)

Deterministic evidence:

```text
Measure Revenue All Customers aggregates tables: Sales
Measure dependencies: Total Revenue
Direction-compatible active paths 'Customer' -> 'Sales': 1
  ACTIVE PATH: 'Customer' -> 'Sales' via 'Sales'[CustomerKey] (many) -> 'Customer'[CustomerKey] (one) [active]
Modifier in Revenue All Customers: REMOVEFILTERS('Customer') [calculate-filter]
```

**#1 [high confidence]** Measure logic removes filters: Revenue All Customers uses REMOVEFILTERS('Customer'). — Static DAX evidence: the filter modifier targets the selected table or the aggregated table, so selections there are ignored by design.

- Compare the measure with its base measure under the same selection.
- If selections must apply, remove the modifier or use KEEPFILTERS/narrower targets.

## Recommended Actions

No findings in this section.

## Limitations


## Evidence Appendix
