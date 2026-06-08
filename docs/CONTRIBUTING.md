# Contributing to Reqlore

## Dev setup

```powershell
git clone https://github.com/ibrasonic/Reqlore.git
cd Reqlore
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e .[dev]
py -m reqlore.cli init demo.rlr
py -m reqlore.cli ui --project demo.rlr
```

## Running tests

```powershell
py -m pytest reqlore/tests/unit -q
py -m pytest reqlore/tests/integration -q     # needs vuln-bank/shop/social
py -m pytest reqlore/tests/a11y -q            # needs playwright + browsers
```

## Adding a feature

1. Open or update an issue describing the user-visible behaviour.
2. Update `docs/FEATURES.md` (✅/🚧/📋).
3. Add or update tests first.
4. Implement.
5. Run axe-core a11y check on any new page.
6. Update `docs/ROADMAP.md` checkbox.

## Style

- Black + ruff defaults (pinned in `pyproject.toml`).
- Type hints required on public functions.
- Docstrings: one-line summary, then sections.
- No `print` in library code — use `logging`.

## Commit / PR rules

- Conventional Commits (`feat: ...`, `fix: ...`, `docs: ...`).
- One PR = one logical change. Refactors separate from features.
- CI must be green: unit + integration + a11y + ruff + mypy.
