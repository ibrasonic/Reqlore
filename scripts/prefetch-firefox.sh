#!/usr/bin/env sh
# Pre-download the official Firefox portable archive into Reqlore's cache.
#
# Usage:
#   ./scripts/prefetch-firefox.sh                 # latest version
#   ./scripts/prefetch-firefox.sh 127.0           # pinned version
#   FORCE=1 ./scripts/prefetch-firefox.sh         # re-download

set -eu

VERSION="${1:-}"
FORCE_FLAG=""
if [ "${FORCE:-0}" = "1" ]; then
    FORCE_FLAG="--force"
fi

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    PYTHON="python"
fi

set -x
if [ -n "$VERSION" ]; then
    "$PYTHON" -m reqlore.cli prefetch-firefox --firefox-version "$VERSION" $FORCE_FLAG
else
    "$PYTHON" -m reqlore.cli prefetch-firefox $FORCE_FLAG
fi
