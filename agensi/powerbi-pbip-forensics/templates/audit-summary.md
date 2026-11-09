# Audit summary template

Use this structure when the user asks for a full audit. Attach or link the report produced by `scripts/pbip_report.py`.

## Executive summary
- Project: <name> · Reports: <n> · Pages: <n> · Visuals: <n> · Tables: <n> · Measures: <n> · Relationships: <n>
- Findings: CRITICAL <n>, HIGH <n>, MEDIUM <n>, LOW <n>, INFO <n> (confirmed <n>, potential <n>, inconclusive <n>)

## Top confirmed problems
1. <ID> <title> (<path:line>). <one-line impact>

## Top risks to verify
1. <ID> <title>. Verify: <verification>

## Performance
<Measured results from the Performance Analyzer log, or: "No runtime measurements available; static risks: ...">

## Recommended next actions (ordered)
1. ...

## Limitations
- Static analysis only; DAX not executed; no data values read.
- <limitations from JSON>
