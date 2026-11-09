# Agensi compliance report (v1.0.0)

Package: `dist/powerbi-pbip-forensics-v1.0.0.zip` (143,691 bytes, 14 files, rebuilt on Windows,
SHA-256 `54f91b20aecff8ebe873e402290471510a775faa174ead12f4858c099ec17a4d`).
The SHA-256 changes if the package is rebuilt after edits; `dist/validation-report.json` holds the current value.

Requirements were checked against https://www.agensi.io/docs/packaging, /docs/submit-on-the-website and
/docs/security, read on 2026-11-08.

**This product has NOT been approved by Agensi.** Approval depends on the platform's own scan and review.

## Verified locally

| Requirement (source) | Check | Result |
|---|---|---|
| One `SKILL.md`, with frontmatter at the start (packaging) | ZIP scan | ✅ exactly 1 |
| `name` and `description` present; optional `summary`, `version`, `tags`, `keywords`, `use_cases` (packaging) | Frontmatter parsed with PyYAML and with the packager's parser | ✅ `version: 1.0.0` |
| A single top-level folder is allowed (packaging) | Layout | ✅ `powerbi-pbip-forensics/` |
| Text-only content; no executables or binaries (packaging) | Extension allowlist (`.md`, `.py`) and UTF-8 decode of every file | ✅ |
| No `node_modules`, `site-packages`, virtual environments, `.git`, `__pycache__`, `.env` (packaging) | Path scan | ✅ none |
| ZIP ≤ 50 MB; ≤ 1,000 files (submission and packaging) | Size and count | ✅ 0.14 MB, 14 files |
| Buyer receives SKILL.md plus ≤ 200 other text files within 6 million characters (packaging) | Count and characters | ✅ 13 other files, 501,515 characters |
| Agent upload limit: 100 files, 5 MB, text only (packaging) | Size and count | ✅ also within these limits |
| Scripts run alone as temporary files and cannot read other package files (packaging) | Each script extracted from the ZIP to a `NamedTemporaryFile` and run with `python -I` from a temporary directory | ✅ 6/6 exit 0 |
| Data needed by scripts is embedded (packaging) | Rule texts, visual type lists and connector names are embedded | ✅ |
| No secrets (security: secrets) | Regex scan for API keys, private keys, tokens and passwords | ✅ none |
| No dangerous commands, network access or environment harvesting (security) | Build-time scan for subprocess/socket/urllib/http/requests, eval/exec/compile/`__import__`, `os.system`/remove/unlink, `shutil.rmtree`, `base64`/zlib, `os.environ` | ✅ none |
| No obfuscation (security) | Scripts are readable, generated Python with Portuguese comments; no encoded payloads | ✅ |
| Prompt-injection hygiene (security) | SKILL.md tells the agent to treat project content as untrusted data; no instructions to bypass agent restrictions | ✅ |
| Name ≤ 60 characters, summary ≤ 300 characters (submission) | "Power BI PBIP Forensics" is 23 characters; listing summary is 297 characters | ✅ |
| No links to outside checkouts (submission) | Text scan | ✅ only the author's GitHub profile in the README (not shipped in the ZIP) |

## Deviations and risks

1. **Script size guideline (packaging) — advisory, not a hard limit.** The packaging page phrases it as "Keep each script's logic under 20 KB"; it is absent from the Limits table and from the pre-submission checks (re-checked 2026-11-09). Decision: no refactor for v1.0.0. Agensi recommends keeping each script's logic under about 20 KB.
   Five of the six scripts exceed it:
   - `pbip_visual_deps.py`: 119 KB total
   - `pbip_model_audit.py`: 110 KB total
   - `pbip_diff.py`: 90 KB total
   - `pbip_inspect.py`: 86 KB total
   - `pbip_report.py`: 35 KB total

   Only `pbip_perf_log.py` (24 KB total, about 17 KB of logic) meets it.

   Reason: each script must run alone, so each one embeds the TMDL, PBIR and DAX parsers and the graph code.
   Splitting would either duplicate the parsers or need a staged JSON pipeline.

   Options: accept the risk, or implement the staged pipeline in v1.1. In that pipeline the inspect script
   writes a normalized inventory and the analysis scripts read that JSON, which removes about 45 KB of
   parsing code from each analysis script.

2. **No license text inside the ZIP.** The licensing model is still undecided (see `docs/licensing-options.md`).
   Add a `LICENSE.md` (EULA) to the skill folder before submission if Agensi or the chosen model requires it.

3. **Performance Analyzer format.** It was validated with synthetic exports only. Validate with a real export
   before publishing the listing claims about performance analysis.

4. **Windows.** Verified on Windows with CPython 3.13.13: 92 passed, 1 skipped (symlink test needs privileges); `package_agensi.py` ok, 6/6 scripts exit 0.

## Depends on Agensi (cannot be verified locally)

- The platform's automated scan (file structure, file types, dangerous commands, secrets, environment
  harvesting, network access, obfuscation, prompt injection) and the human review outcome.
- Auto-detected permissions shown on the listing. The expected permissions are: run local Python scripts;
  read folders the user provides; write to an output folder. No network.
- Uniqueness of the name and package across Agensi.
- Whether the 20 KB script guideline is enforced or only advisory.
- Category names. Pick up to 3 from the 32 categories in the submission form.
- Payout setup for a paid listing (price US$ 19 meets the US$ 1 minimum).
