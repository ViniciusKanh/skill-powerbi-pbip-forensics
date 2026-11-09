# Question playbook

Worked mappings from user questions to scripts and to the evidence to cite. All examples use the synthetic
project bundled with the product (fictional "ContosoRetail" data).

## 1. "Why is this table showing unrelated customers/accounts?"

Run:

```bash
python scripts/pbip_visual_deps.py --project <P> --from-table Customer --to-table Account --visual "Customer Accounts"
python scripts/pbip_model_audit.py --project <P>
```

Look for:

- **VIS006**: unrelated tables combined in a table or matrix.
- **VIS005**: grouping table cannot filter the measure.
- **MOD002**: inactive relationship.
- **MOD008**: disconnected table.
- **Investigation**: blocked paths marked `[INACTIVE]`, or "direction does not allow".

Typical structural causes, in order:

1. An inactive relationship on the only path.
2. A single-direction relationship that would need to flow from the many side to the one side.
3. No relationship at all.
4. Measure logic that removes filters (ALL/REMOVEFILTERS).

If none of these applies, the remaining causes are data-level (unmatched keys or a blank member) or
interaction-level (Edit interactions, bookmarks, sync slicers). Present those as low confidence.

## 2. "My total revenue is different from the visible rows."

Run `pbip_model_audit.py`, then:

```bash
pbip_visual_deps.py --project <P> --from-table <row table> --measure "<measure>"
```

Look for:

- **DAX008**: IF/SWITCH evaluated at the total level, HASONEVALUE/ISINSCOPE/SELECTEDVALUE branches, or DISTINCTCOUNT.
- **DAX006**: filter removal.
- **MOD004**: many-to-many relationship.
- **VIS005**: grouping does not filter the measure, so every row may repeat the total.

Explain that Power BI re-evaluates a measure in the total's filter context; it does not sum the rows.
Do not state what the total "should" be.

## 3. "Which visuals are causing my report to load slowly?"

With a log, run:

```bash
python scripts/pbip_perf_log.py --input <export.json>
```

Report the measured ranking. Cite the dominant component for each visual: DAX query, Direct query,
Visual display or Other.

Without a log, say that no measurements are available. List DAX003/DAX004/DAX005/DAX010 and VIS004 as
**static risks** to prioritize when profiling, and ask the user to export a Performance Analyzer session.
Never infer slowness from the number of measures in a visual.

## 4. "Which relationships could be preventing the customer filter from propagating?"

Run `pbip_model_audit.py` and `pbip_visual_deps.py --from-table Customer --to-table <target>`.

Cite:

- every hop in the blocked paths;
- inactive relationships (MOD002);
- single-direction hops against the needed flow;
- bidirectional relationships that create ambiguous paths (MOD003, MOD006 HIGH);
- CROSSFILTER(..., NONE) in the measure (DAX006).

## 5. "What will this change break?"

Run `pbip_diff.py --before OLD --after NEW`. Then run `pbip_visual_deps.py --project NEW` to see whether
removed objects are still bound (VIS001/VIS002 are confirmed breaks).

Wording: "Measure 'X' changed. The following visuals reference it and may require regression testing."
A token-level change is not proof of a functional regression. A `modified-formatting` change (whitespace
or comments only) needs no functional test.

## 6. "Is this measure ever used?"

Look for DAX011. It is produced only when every report bound to the model is PBIR and fully interpretable.
Always add: "other reports connected to the published model were not analyzed."
