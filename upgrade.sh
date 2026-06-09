#!/usr/bin/env sh
# Reqlore upgrader — Linux / macOS.
#
# Usage (from inside the cloned repo):
#   sh upgrade.sh         # or: ./upgrade.sh after `chmod +x upgrade.sh`
#
# What it does:
#   1. Pulls the latest source from this repo (git pull --ff-only), if you
#      ran from a clone with a tracking branch. Skipped if there's no .git.
#   2. Detects an existing install:
#        - pipx (preferred)  -> pipx install --force . (clean reinstall)
#        - local .venv       -> .venv/bin/pip install --upgrade .
#        - nothing installed -> defers to install.sh
#   3. Purges any stale `pip install --user reqlore` shim that would
#      otherwise shadow the pipx install on PATH.
#
# Environment overrides:
#   PYTHON=python3.12       pick a specific interpreter
#   REQLORE_VENV=.venv      venv location for the venv path
#   REQLORE_NO_PIPX=1       skip pipx detection; upgrade venv only
#   REQLORE_NO_GIT=1        skip the `git pull` step
set -eu

PYTHON="${PYTHON:-python3}"

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }
warn() { printf 'warn: %s\n' "$*" >&2; }

[ -f "pyproject.toml" ] || die "run this from the Reqlore repository root (pyproject.toml not found)."
grep -q '^name = "reqlore"' pyproject.toml \
    || die "this directory's pyproject.toml is not Reqlore's. Are you in the right folder?"

command -v "$PYTHON" >/dev/null 2>&1 \
    || die "$PYTHON not found. Install Python 3.12+ and re-run (override with PYTHON=...)."

"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
    || die "Python 3.12+ required (have: $("$PYTHON" --version 2>&1))."

# ---- 1. refresh source via git (best-effort) -------------------------------
if [ "${REQLORE_NO_GIT:-0}" != "1" ] && [ -d ".git" ] && command -v git >/dev/null 2>&1; then
    info "pulling latest from the tracking branch"
    if ! git pull --ff-only; then
        warn "git pull failed — upgrading from the current working tree as-is."
    fi
fi

# Make sure ~/.local/bin (where pipx puts shims) is visible for `command -v`.
PATH="$HOME/.local/bin:$PATH"
export PATH

has_pipx_reqlore() {
    command -v pipx >/dev/null 2>&1 || return 1
    pipx list 2>/dev/null | grep -q '^   package reqlore ' || return 1
    return 0
}

upgrade_pipx() {
    info "upgrading Reqlore via pipx (clean reinstall from this checkout)"

    # A previous `pip install --user reqlore` could leave a shim that
    # shadows the pipx install on PATH. Wipe it before pipx puts its own
    # fresh shim back.
    "$PYTHON" -m pip uninstall -y reqlore >/dev/null 2>&1 || true

    pipx ensurepath >/dev/null 2>&1 || true

    # Kill any running reqlore / pipx-venv python so files unlock. Then do
    # a full uninstall before reinstalling. `pipx install --force` can
    # silently no-op when the version string hasn't bumped or when venv
    # files are locked — full uninstall + install is the only reliable
    # sequence.
    if command -v pkill >/dev/null 2>&1; then
        pkill -f "$HOME/pipx/venvs/reqlore/bin/" 2>/dev/null || true
        pkill -x reqlore                          2>/dev/null || true
    fi

    # Clear pipx's trash (same reasoning as in install.sh).
    rm -rf "$HOME/pipx/trash" 2>/dev/null || true
    pipx uninstall reqlore >/dev/null 2>&1 || true
    rm -rf "$HOME/pipx/trash" 2>/dev/null || true

    pipx install .

    echo
    info "upgraded."
    echo
    pipx list 2>/dev/null | grep '^   package reqlore ' || true
    echo
    echo "Run (open a new shell if PATH hasn't refreshed):"
    echo "  reqlore --version"
    echo "  reqlore --help"
}

upgrade_venv() {
    VENV="${REQLORE_VENV:-.venv}"
    [ -x "$VENV/bin/pip" ] || die "no venv at $VENV to upgrade. Run install.sh first."

    info "upgrading Reqlore in venv at $VENV"
    "$VENV/bin/pip" install --upgrade pip >/dev/null
    "$VENV/bin/pip" install --upgrade .

    echo
    info "upgraded."
    echo
    echo "Run:"
    echo "  ./$VENV/bin/reqlore --version"
    echo "  ./$VENV/bin/reqlore --help"
}

# ---- 2. decide path: pipx, venv, or neither --------------------------------
if [ "${REQLORE_NO_PIPX:-0}" != "1" ] && has_pipx_reqlore; then
    upgrade_pipx
    exit 0
fi

VENV="${REQLORE_VENV:-.venv}"
if [ -x "$VENV/bin/pip" ]; then
    upgrade_venv
    exit 0
fi

info "no existing Reqlore install found — running install.sh for a fresh setup."
exec sh ./install.sh
