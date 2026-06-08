#!/usr/bin/env sh
# Weblore installer — Linux / macOS.
#
# Usage (from inside the cloned repo):
#   sh install.sh        # or: ./install.sh after `chmod +x install.sh`
#
# What it does:
#   1. Verifies Python 3.12+ is present.
#   2. If pipx is installed, uses it (preferred — isolates Weblore in its own
#      venv and puts `weblore` on your PATH).
#   3. Otherwise creates a venv in ./.venv and installs into it; you'll need
#      to activate the venv (or call the absolute path) to run `weblore`.
#
# Environment overrides:
#   PYTHON=python3.12     pick a specific interpreter
#   WEBLORE_VENV=.venv    venv location for the fallback path
set -eu

PYTHON="${PYTHON:-python3}"

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }

# Refuse to install from the wrong directory — pip would silently grab the PyPI
# package (or fail) if pyproject.toml is missing, which is exactly the trap we
# wrote this script to avoid.
[ -f "pyproject.toml" ] || die "run this from the Weblore repository root (pyproject.toml not found)."
grep -q '^name = "weblore"' pyproject.toml \
    || die "this directory's pyproject.toml is not Weblore's. Are you in the right folder?"

# ---- 1. Python ----
command -v "$PYTHON" >/dev/null 2>&1 \
    || die "$PYTHON not found. Install Python 3.12+ and re-run (override with PYTHON=...)."

"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
    || die "Python 3.12+ required (have: $("$PYTHON" --version 2>&1))."

# ---- 2. pipx fast path ----
if command -v pipx >/dev/null 2>&1; then
    info "pipx detected — installing Weblore as an isolated CLI"
    pipx install --force .
    info "done."
    info ""
    info "Try it:"
    info "  weblore --help"
    info "  weblore init demo.weblore"
    info "  weblore both --project demo.weblore"
    info ""
    info "If 'weblore' isn't found, run: pipx ensurepath  (then open a new shell)"
    exit 0
fi

# ---- 3. venv fallback ----
VENV="${WEBLORE_VENV:-.venv}"

if [ ! -d "$VENV" ]; then
    info "creating virtual environment at $VENV"
    if ! "$PYTHON" -m venv "$VENV" 2>/dev/null; then
        die "failed to create venv. On Debian/Ubuntu/Kali install the venv module first:
  sudo apt install python3-venv
On Fedora/RHEL:
  sudo dnf install python3-virtualenv
Then re-run this script."
    fi
fi

info "upgrading pip"
"$VENV/bin/pip" install --upgrade pip >/dev/null

info "installing Weblore (this pulls mitmproxy and is ~150 MB; first run can take a few minutes)"
"$VENV/bin/pip" install .

info "done."
echo
echo "Weblore is installed into the venv at: $VENV"
echo
echo "Run it without activating (simplest):"
echo "  ./$VENV/bin/weblore init demo.weblore"
echo "  ./$VENV/bin/weblore both --project demo.weblore"
echo
echo "Or activate the venv first and use the bare command:"
echo "  source $VENV/bin/activate"
echo "  weblore init demo.weblore"
echo "  weblore both --project demo.weblore"
echo
echo "Tip: 'pipx install .' (after 'sudo apt install pipx') gives you a global"
echo "     'weblore' command without the activation step."
