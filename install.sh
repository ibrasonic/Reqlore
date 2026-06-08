#!/usr/bin/env sh
# Reqlore installer — Linux / macOS.
#
# Usage (from inside the cloned repo):
#   sh install.sh        # or: ./install.sh after `chmod +x install.sh`
#
# What it does:
#   1. Verifies Python 3.12+ is present.
#   2. Ensures pipx is installed — tries (in order) the system package
#      manager (apt/dnf/pacman/zypper/apk/brew) then `pip install --user pipx`.
#      Uses sudo automatically if present.
#   3. Runs `pipx install .` so you get a global `reqlore` command.
#   4. If steps 2-3 all fail, falls back to a local ./.venv install.
#
# Environment overrides:
#   PYTHON=python3.12       pick a specific interpreter
#   REQLORE_VENV=.venv      venv location for the fallback path
#   REQLORE_NO_PIPX=1       skip pipx entirely; go straight to venv
set -eu

PYTHON="${PYTHON:-python3}"

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }
warn() { printf 'warn: %s\n' "$*" >&2; }

# Run a command with sudo if we're not already root and sudo exists.
maybe_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        return 127
    fi
}

# Refuse to install from the wrong directory — pip would silently grab the PyPI
# package (or fail) if pyproject.toml is missing, which is exactly the trap we
# wrote this script to avoid.
[ -f "pyproject.toml" ] || die "run this from the Reqlore repository root (pyproject.toml not found)."
grep -q '^name = "reqlore"' pyproject.toml \
    || die "this directory's pyproject.toml is not Reqlore's. Are you in the right folder?"

# ---- 1. Python ----
command -v "$PYTHON" >/dev/null 2>&1 \
    || die "$PYTHON not found. Install Python 3.12+ and re-run (override with PYTHON=...)."

"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
    || die "Python 3.12+ required (have: $("$PYTHON" --version 2>&1))."

# ---- 2. pipx: install if missing, then use it ------------------------------

install_pipx() {
    # Try the system package manager appropriate to this host. Return 0 on
    # success, non-zero if no path worked.
    if command -v apt-get >/dev/null 2>&1; then
        info "installing pipx via apt"
        maybe_sudo apt-get update -y >/dev/null 2>&1 || true
        maybe_sudo apt-get install -y pipx && return 0
    fi
    if command -v dnf >/dev/null 2>&1; then
        info "installing pipx via dnf"
        maybe_sudo dnf install -y pipx && return 0
    fi
    if command -v pacman >/dev/null 2>&1; then
        info "installing pipx via pacman"
        maybe_sudo pacman -S --noconfirm python-pipx && return 0
    fi
    if command -v zypper >/dev/null 2>&1; then
        info "installing pipx via zypper"
        maybe_sudo zypper install -y python3-pipx && return 0
    fi
    if command -v apk >/dev/null 2>&1; then
        info "installing pipx via apk"
        maybe_sudo apk add --no-cache pipx && return 0
    fi
    if command -v brew >/dev/null 2>&1; then
        info "installing pipx via Homebrew"
        brew install pipx && return 0
    fi
    # Last resort: pip --user. Works on any platform with Python+pip.
    info "no system package manager matched; installing pipx via pip --user"
    "$PYTHON" -m pip install --user pipx && {
        # pip --user puts scripts in a directory that may not be on PATH yet.
        # Try the canonical spot so the very next `command -v pipx` finds it.
        PATH="$HOME/.local/bin:$PATH"
        export PATH
        return 0
    }
    return 1
}

use_pipx() {
    if [ "${REQLORE_NO_PIPX:-0}" = "1" ]; then
        return 1
    fi
    if ! command -v pipx >/dev/null 2>&1; then
        if ! install_pipx; then
            warn "couldn't install pipx automatically — falling back to local venv"
            return 1
        fi
    fi
    # pipx ensurepath is idempotent and quiet on second run; do it once so the
    # user's shells pick up ~/.local/bin without them having to know about it.
    pipx ensurepath >/dev/null 2>&1 || true
    PATH="$HOME/.local/bin:$PATH"
    export PATH

    info "installing Reqlore with pipx (isolated CLI on PATH)"
    pipx install --force .
    info "done."
    echo
    echo "Try it:"
    echo "  reqlore --help"
    echo "  reqlore init demo.rlr"
    echo "  reqlore both --project demo.rlr"
    echo
    echo "If 'reqlore' is not found, open a new shell (so PATH picks up ~/.local/bin)."
    return 0
}

if use_pipx; then
    exit 0
fi

# ---- 3. venv fallback ------------------------------------------------------
VENV="${REQLORE_VENV:-.venv}"

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

info "installing Reqlore (this pulls mitmproxy and is ~150 MB; first run can take a few minutes)"
"$VENV/bin/pip" install .

info "done."
echo
echo "Reqlore is installed into the venv at: $VENV"
echo
echo "Run it without activating (simplest):"
echo "  ./$VENV/bin/reqlore init demo.rlr"
echo "  ./$VENV/bin/reqlore both --project demo.rlr"
echo
echo "Or activate the venv first and use the bare command:"
echo "  source $VENV/bin/activate"
echo "  reqlore init demo.rlr"
echo "  reqlore both --project demo.rlr"
