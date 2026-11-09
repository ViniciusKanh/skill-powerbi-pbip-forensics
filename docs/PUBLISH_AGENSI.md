# Publishing on Agensi — checklist

## Before upload
1. Decide the license. If approved, copy `docs/LICENSE-COMMERCIAL-DRAFT.md` (final text) to `agensi/powerbi-pbip-forensics/LICENSE.md`, then run `python tools/package_agensi.py` (Python 3.11+) to rebuild and validate the ZIP.
2. On Windows (Python 3.11+), from the repo root:
   ```powershell
   py -3.11 --version
   py -3.11 -m pip install pytest
   py -3.11 -m pytest -o addopts="" -q
   py -3.11 tools\package_agensi.py
   ```
   Expected: `93 passed` and `"ok": true`. Check `dist\validation-report.json`.
3. Optional but recommended: export a real Performance Analyzer log and run
   `py -3.11 agensi\powerbi-pbip-forensics\scripts\pbip_perf_log.py --input <export.json>`. Until then, keep the "preview" wording.

## Upload (agensi.io/dashboard/submit)
1. ZIP: `dist/powerbi-pbip-forensics-v1.0.0.zip`.
2. Fill fields from `docs/agensi-listing.md`: Name, Summary (≤300 chars), Description, "See it in action", Limitations, Compatibility note (Python 3.11+, standard library only).
3. Price: US$ 19 (requires a payout method). Categories: up to 3 closest to Data & Analytics / Developer Tools / QA. Tags and use cases from the listing.
4. Review the auto-detected permissions: should be local file read/write and running Python scripts; no network.
5. Do not add external checkout links. Submit; status stays pending until scan and review finish.

## Post-publication test
1. Install the purchased/published skill in your agent (e.g., Claude Code) in a clean folder.
2. Copy `examples/synthetic_project` to a test folder and ask: "Why is the 'Customer Accounts' table showing accounts unrelated to the selected customer?"
3. Expected: the agent asks for authorization, runs `pbip_visual_deps.py` and `pbip_model_audit.py`, cites VIS006 and MOD002 (relationships.tmdl:27), separates evidence from reasoning and states limitations.
4. Ask "Audit this project and generate a report" → `pbip_report.py` produces `audit-report.md/html`.
5. Confirm no file inside the project changed and outputs were written only to the chosen output folder.
