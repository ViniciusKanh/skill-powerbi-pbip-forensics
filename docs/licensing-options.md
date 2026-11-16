# Licensing options (decision pending)

The repository is **proprietary ("All rights reserved")** until the author decides. No open-source license
has been applied. This page describes the alternatives and is not legal advice. Consult a lawyer before
choosing.

| Option | What buyers can do | Fit for an Agensi paid skill | Notes |
|---|---|---|---|
| Proprietary EULA (per-user) | Use for themselves; no redistribution or resale | Strong | Most common for paid skills. Needs a short EULA text inside the ZIP (e.g., `LICENSE.md`). |
| Proprietary EULA (per-organization) | Use inside one company | Strong | Allows a higher price tier for teams. |
| Source-available (e.g., PolyForm Noncommercial / Business Source License) | Read and modify; commercial use restricted or delayed | Medium | Keeps code visible while protecting commercial use; BSL converts to open source after a set date. |
| Dual license (open-source core + commercial skill) | Engine under a permissive or copyleft license; skill and support paid | Medium | Builds community trust; the value moves to the skill, updates and support. |
| Open source (MIT / Apache-2.0) | Anything, including resale | Weak for direct sales | Only if the business model is support or consulting. |
| Copyleft (GPL-3.0 / AGPL-3.0) | Use and modify; derivatives must stay open | Weak | Can deter corporate buyers. |

## Before choosing

- Agensi marketplace terms: check them for license requirements and buyer rights.
- Whether buyers may run the skill on client projects as consultants.
- Whether the ZIP should include a `LICENSE.md` with an EULA summary.
- The trademark notice: Microsoft and Power BI names are used only descriptively.

Until then, keep the repository private and do not push it to a public remote.

## Packaging note (2026-11, Python CLI distribution)

`pyproject.toml` now declares the license as the SPDX expression `license = "LicenseRef-Proprietary"`
(PEP 639), with `LICENSE` shipped via `license-files`. This is a **metadata-format** change only —
the software is exactly as proprietary as before ("All rights reserved", no license granted without
a separate agreement). The change was needed because the previous
`license = {text = "..."}` + `"License :: Other/Proprietary License"` classifier combination is
deprecated by setuptools and stops building after 2027-02-18. The `Private :: Do Not Upload`
classifier is kept, so PyPI still refuses any accidental upload until it is deliberately removed.
See [docs/python-packaging.md](python-packaging.md) for the full packaging and future-publication
procedure (not executed).
