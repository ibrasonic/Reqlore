#!/usr/bin/env sh
# Reqlore uninstaller — Linux / macOS.
#
# Usage (from inside the cloned repo):
#   sh uninstall.sh
#
# What it removes:
#   - The pipx-installed `reqlore` (if present).
#   - The local ./.venv (or $REQLORE_VENV) created by install.sh.
#
# What it does NOT remove (you have to opt in):
#   - Your project files (*.rlr SQLite DBs) — pass --purge-data.
#   - The pipx tool itself — that's the system package manager's job.
#   - The mitmproxy CA you may have trusted in your browser/OS keystore.
#
# Environment overrides:
#   REQLORE_VENV=.venv      where the venv lives (matches install.sh)
set -eu

PURGE_DATA=0
for arg in "$@"; do
    case "$arg" in
        --purge-data) PURGE_DATA=1 ;;
        -h|--help)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) printf 'unknown flag: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

info() { printf '==> %s\n' "$*"; }
warn() { printf 'warn: %s\n' "$*" >&2; }

removed_any=0

# ---- 1. pipx-installed reqlore --------------------------------------------
if command -v pipx >/dev/null 2>&1; then
    if pipx list 2>/dev/null | grep -q '^   package reqlore '; then
        info "removing pipx-installed reqlore"
        pipx uninstall reqlore && removed_any=1
    fi
fi

# ---- 1b. user-site `pip install --user` reqlore (stale shim trap) ---------
# A leftover `pip install --user reqlore` leaves a shim in ~/.local/bin that
# can shadow the pipx install. Detect and remove it so `reqlore` resolves
# cleanly after a re-install.
for _py in python3 python; do
    if command -v "$_py" >/dev/null 2>&1; then
        if "$_py" -m pip show reqlore >/dev/null 2>&1; then
            info "removing stale user-site reqlore (pip --user shim)"
            "$_py" -m pip uninstall -y reqlore >/dev/null 2>&1 && removed_any=1
        fi
        break
    fi
done

# ---- 2. local venv ---------------------------------------------------------
VENV="${REQLORE_VENV:-.venv}"
if [ -d "$VENV" ]; then
    # Best-effort: stop processes holding files in the venv (mitmproxy, reqlore
    # itself). Failure is fine — rm -rf will report what's locked.
    if command -v pkill >/dev/null 2>&1; then
        pkill -f "$PWD/$VENV/bin/" 2>/dev/null || true
    fi
    info "removing venv at $VENV"
    rm -rf "$VENV" && removed_any=1
fi

# ---- 3. project data (opt-in) ----------------------------------------------
if [ "$PURGE_DATA" = "1" ]; then
    if [ -d "data" ]; then
        info "removing ./data (project files)"
        rm -rf data && removed_any=1
    fi
    # Common name from the README quickstart.
    for f in demo.rlr demo.rlr-journal demo.rlr-wal demo.rlr-shm; do
        [ -e "$f" ] && { info "removing $f"; rm -f "$f"; removed_any=1; }
    done
fi

if [ "$removed_any" = "0" ]; then
    info "nothing to remove — Reqlore doesn't appear to be installed here."
    exit 0
fi

info "done."
echo
echo "Not touched by this script (remove manually if you want):"
echo "  - pipx itself (apt remove pipx / dnf remove pipx / brew uninstall pipx)"
echo "  - the mitmproxy CA you installed in your browser/OS keystore"
[ "$PURGE_DATA" = "0" ] && echo "  - your *.rlr project files (re-run with --purge-data to also drop these)"
