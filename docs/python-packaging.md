# Python packaging & publishing

This page documents how `powerbi-pbip-forensics` is packaged as a pip-installable CLI
(`pbip-forensics`), what has been verified, and the procedure to publish it on TestPyPI/PyPI —
**not executed as part of this work**, pending the author's explicit authorization and a final
licensing decision (see [licensing-options.md](licensing-options.md)).

## What this covers vs. the Agensi skill

This repository ships **two independent distribution channels** for the same engine
(`src/pbip_forensics/`):

| | Agensi skill | Python package |
|---|---|---|
| Artifact | `dist/powerbi-pbip-forensics-v1.0.0.zip` | `dist/powerbi_pbip_forensics-1.0.0-{py3-none-any.whl,tar.gz}` |
| Built by | `tools/build_skill.py` + `tools/package_agensi.py` | `python -m build` |
| Consumed by | AI agents (Claude Code, etc.) that read `SKILL.md` and run standalone scripts | Any Python 3.11+ environment, via `pip install` and the `pbip-forensics` command |
| Distributed via | Agensi marketplace | Not yet distributed anywhere (see below) |

They are built from the same source and validated independently; building one does not
affect the other (see `tests/integration/test_skill_scripts.py` for skill parity and
`tests/packaging/test_distribution.py` for the pip package).

## Status as of this work

- The package builds cleanly with `python -m build` (wheel + sdist), and both pass
  `python -m twine check dist/*`.
- Both the wheel and the sdist were installed in **isolated, throwaway virtual environments**
  (outside the repository) on Python 3.11, 3.12 and 3.13, and the `pbip-forensics` CLI (and
  `python -m pbip_forensics`) worked correctly from a different working directory, with no
  `PYTHONPATH` set.
- `pyproject.toml` declares the license as the SPDX expression `LicenseRef-Proprietary` (PEP 639),
  with the original `LICENSE` file shipped via `license-files`. This keeps the software exactly as
  proprietary as before — only the *metadata format* changed, because the previous
  `license = {text = "..."}` table combined with a `License :: Other/Proprietary License`
  classifier is deprecated by setuptools and will stop building after **2027-02-18**.
- The `Private :: Do Not Upload` classifier was kept until 2026-11-16, when it was **removed at the
  author's explicit request** as the deliberate step enabling the first real PyPI upload (the author
  already holds a PyPI account and generated an API token for this). This is noted in `CHANGELOG.md`.
- **Published on PyPI on 2026-11-16**: https://pypi.org/project/powerbi-pbip-forensics/1.0.0/.
  The upload itself was run by the author locally (`twine upload`) with their own PyPI API token,
  which was intentionally never shared in this session. No GitHub Release and no git tag have been
  created to mark this release yet (optional follow-up, not done).

## Checking the name on PyPI / TestPyPI

- `https://pypi.org/pypi/powerbi-pbip-forensics/json` returned **404** when checked during this
  work, i.e. the name `powerbi-pbip-forensics` is currently available on PyPI.
- TestPyPI (`https://test.pypi.org`) could **not** be reached from this build environment (network
  egress to that host is blocked here), so its availability was not verified. Check it manually
  before the first TestPyPI upload: `https://test.pypi.org/project/powerbi-pbip-forensics/`.
- If the name is ever taken on either index by the time of publication, do **not** silently rename
  the distribution. Stop and present alternatives to the author (e.g. a suffix, a different
  separator, or a namespaced name), per the project's instructions.

## Building locally

```bash
pip install -e ".[dev]"      # pulls in build, twine, setuptools, wheel, pytest, ruff, mypy
python -m build               # writes dist/*.whl and dist/*.tar.gz
python -m twine check dist/*.whl dist/*.tar.gz
```

## First publication to TestPyPI (when authorized)

1. **Decide the license.** Read [licensing-options.md](licensing-options.md) and pick a model
   (proprietary EULA, source-available, etc.). Update `LICENSE` and the `license` field in
   `pyproject.toml` if the decision changes anything (the current `LicenseRef-Proprietary` already
   fits a proprietary EULA model).
2. **Remove the safety classifier** `Private :: Do Not Upload` from `pyproject.toml` — this is the
   explicit, deliberate step that allows an upload to succeed. Do this only when ready to publish.
3. **Rebuild** with `python -m build` so the new metadata is reflected in the artifacts.
4. **Create a TestPyPI API token** (https://test.pypi.org/manage/account/#api-tokens, after
   registering an account) or set up Trusted Publishing (recommended — see below).
5. **Upload**:
   ```bash
   python -m twine upload --repository testpypi dist/*.whl dist/*.tar.gz
   ```
6. **Verify the install** from TestPyPI in a clean venv:
   ```bash
   python -m venv /tmp/testpypi-check && source /tmp/testpypi-check/bin/activate
   pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ powerbi-pbip-forensics
   pbip-forensics --version
   ```
   (`--extra-index-url` is needed because `powerbi-pbip-forensics` has no runtime dependencies, but
   this pattern is required in general when a TestPyPI package depends on real PyPI packages.)

## First publication to PyPI (when authorized)

Same steps as TestPyPI, pointed at the real index:

```bash
python -m twine upload dist/*.whl dist/*.tar.gz
```

Afterwards:

- `pip install powerbi-pbip-forensics` works for anyone.
- `pip install powerbi-pbip-forensics==1.0.0` pins the version.
- `pip install --upgrade powerbi-pbip-forensics` upgrades.
- `pip uninstall powerbi-pbip-forensics` removes it.

**A version can never be re-uploaded or overwritten on PyPI.** If something is wrong post-publish,
bump the version (see [Versioning](#versioning)) and publish a new one.

## Trusted Publishing (recommended over long-lived tokens)

PyPI's [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) uses OpenID Connect (OIDC)
so GitHub Actions can publish without storing a PyPI token as a repository secret. A *separate*
publish workflow (not `.github/workflows/python-package-ci.yml`, which never publishes) would:

- Trigger only on an explicit, author-created tag matching `pbip-forensics-v*` (e.g.
  `pbip-forensics-v1.0.0`) — **no tag has been created as part of this work.**
- Run in a protected GitHub Environment named `pypi` (configure required reviewers there for human
  approval before the job runs, if your plan supports protected environments).
- Grant `id-token: write` **only** to the publish job, nothing else.
- Verify the tag's version matches `pyproject.toml`'s `version` before publishing, and refuse to
  publish a version that already exists on the index.
- Use `pypa/gh-action-pypi-publish` (configured for Trusted Publishing, no `password`/token input)
  rather than passing a `TWINE_PASSWORD` secret.

Example skeleton (**not added to the repository** — this is reference material for when
publication is authorized; adjust the tag pattern, environment name and approval gates to your
actual GitHub plan and org policy before using it):

```yaml
name: Publish to PyPI
on:
  push:
    tags:
      - "pbip-forensics-v*"
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi          # configure required reviewers on this environment in repo settings
    permissions:
      id-token: write          # only this job gets it; nothing else in the repo needs it
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: python -m pip install build
      - run: python -m build
      - name: Verify tag matches pyproject.toml version
        run: |
          TAG_VERSION="${GITHUB_REF_NAME#pbip-forensics-v}"
          PKG_VERSION=$(python -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
          test "$TAG_VERSION" = "$PKG_VERSION"
      - uses: pypa/gh-action-pypi-publish@release/v1
        # No `with: password:` — Trusted Publishing uses OIDC, not a stored token.
```

### Branch/tag strategy without touching `main`

A tag can point at any commit, including one on `feat/pbip-forensics-python-cli`, without that
branch ever being merged into `main`. So the first release **can** be cut from the development
branch: `git tag pbip-forensics-v1.0.0 <commit-on-feat-branch> && git push origin pbip-forensics-v1.0.0`
(again: **do not run this** without the author's explicit go-ahead — no tag has been created here).
If your organization's branch-protection rules require releases to come from `main`, that is a
policy decision for the author to make later, not something this work assumes or changes.

### If GitHub Actions has an operational limitation

If Trusted Publishing or protected environments are unavailable on your GitHub plan, a manual
publish by the author from a local machine remains safe and simple:

```bash
python -m build
python -m twine check dist/*.whl dist/*.tar.gz
python -m twine upload dist/*.whl dist/*.tar.gz    # prompts for a PyPI API token
```

## Versioning

Semantic Versioning (`MAJOR.MINOR.PATCH`), matching the version already declared in
`pyproject.toml`'s `project.version` (read dynamically as `pbip_forensics.__version__` via
`pbip_forensics.models.TOOL_VERSION` — there is a single source of truth, no duplicated version
string to keep in sync):

- **PATCH** (`1.0.x`): bug fixes, documentation, packaging-only changes, no behavior change.
- **MINOR** (`1.x.0`): new compatible functionality (a new rule, a new CLI flag, a new report
  section) that does not break existing output consumers.
- **MAJOR** (`x.0.0`): incompatible changes — a renamed/removed CLI flag or subcommand, a changed
  exit-code meaning, a changed finding ID scheme, or a changed report schema that existing
  automation could depend on.

Never publish a version that already exists on the index (PyPI rejects it anyway), and never
create a release tag for a version that has not actually been built and tested.
