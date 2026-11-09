# Investigation response template

Use this structure for every answer produced with this skill. Keep script evidence and agent reasoning separate.

## Question
<Restate the technical question: selection/filter source → expected target (table, measure, visual), or performance / change impact.>

## Scope analyzed
- Folders (read-only): <project folder(s)>
- Scripts run: <script names and key arguments>
- Not analyzed: <missing log, byConnection model, unparsed files...>

## Evidence (deterministic, from scripts)
| Finding ID | Severity | Status | Source (path:line) | Evidence |
|---|---|---|---|---|
| <VIS006-xxxxxxxx> | <HIGH> | <potential> | <path> | <evidence lines> |

Investigation hypotheses produced by the scripts (ranked):
1. [<confidence>] <hypothesis>. Justification: <justification>

## Agent reasoning (not produced by the scripts)
<Your interpretation that links the evidence to the symptom. Label every assumption.>

## Recommended verification sequence
1. <Step from the finding's "verification" field or the hypothesis steps>
2. ...

## Possible fixes (not applied, read-only analysis)
- <Recommendation, with the finding ID it addresses>

## Limitations
- Static analysis: DAX was not executed and no data values were read.
- <Items from the JSON "limitations" arrays>
