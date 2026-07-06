#!/bin/sh
# =============================================================================
# Reqlore container entrypoint.
#
# The container must bind 0.0.0.0 *internally* so Docker's host port-forward
# can deliver traffic to the UI. That trips Reqlore's guard:
#   "--unsafe-bind requires a password".
#
# Rather than disable auth with --no-password, this wrapper manages a
# persisted argon2id password hash inside the /data volume so the UI login
# gate is always active:
#
#   * First time (interactive):
#         docker compose run --rm reqlore set-password
#     prompts you twice (hidden) and stores the hash in /data/.reqlore-auth.
#
#   * Every start:
#     the stored hash is loaded into REQLORE_PASSWORD_HASH, satisfying
#     --unsafe-bind and enabling the /login gate for non-loopback clients.
#
# Commands that do not bind a socket (e.g. `init`) skip all of this.
#
# Only the argon2id HASH is ever written to disk -- never the plaintext, and
# the hash is not reversible.
# =============================================================================
set -eu

DATA_DIR="${REQLORE_DATA:-/data}"
HASH_FILE="$DATA_DIR/.reqlore-auth"

# --------------------------------------------------------------- helpers
_hash_password() {
    # Reads the plaintext from env REQLORE__PW, prints an argon2id hash.
    # The hash string is self-describing, so the app can verify it
    # regardless of the cost parameters used to create it here.
    REQLORE__PW="$1" python - <<'PY'
import os
from argon2 import PasswordHasher
print(PasswordHasher().hash(os.environ["REQLORE__PW"]), end="")
PY
}

_have_tty() {
    # True only if /dev/tty can actually be opened (the node can exist as a
    # dangling device with no controlling terminal, e.g. `docker run` without
    # -it, in which case opening it fails with ENXIO).
    ( : < /dev/tty ) 2>/dev/null
}

_read_secret() {
    # _read_secret <var_name> <prompt>: read one line of hidden input from
    # the controlling terminal into the named variable.
    printf '%s' "$2" > /dev/tty
    stty -echo < /dev/tty 2>/dev/null || true
    read -r _secret_val < /dev/tty
    stty echo < /dev/tty 2>/dev/null || true
    printf '\n' > /dev/tty
    eval "$1=\$_secret_val"
    unset _secret_val
}

_set_password() {
    if ! _have_tty; then
        echo "error: setting a password needs an interactive terminal." >&2
        echo "Run:  docker compose run --rm reqlore set-password" >&2
        exit 1
    fi
    _read_secret _p1 "Set a Reqlore UI password: "
    _read_secret _p2 "Confirm password: "
    if [ -z "$_p1" ]; then
        echo "error: password must not be empty." >&2
        exit 1
    fi
    if [ "$_p1" != "$_p2" ]; then
        echo "error: passwords did not match." >&2
        exit 1
    fi
    _h="$(_hash_password "$_p1")"
    unset _p1 _p2
    ( umask 077; printf '%s' "$_h" > "$HASH_FILE" )
    chmod 600 "$HASH_FILE" 2>/dev/null || true
    unset _h
    echo "Password saved to $HASH_FILE (argon2id hash, not reversible)." >&2
}

# ----------------------------------------------------------- subcommands
# `set-password` / `passwd` / `reset-password`: interactive (re)set, exit.
case "${1:-}" in
    set-password|passwd|reset-password)
        _set_password
        echo "Done. Start Reqlore with:  docker compose up -d" >&2
        exit 0
        ;;
esac

# --------------------------------------------------------- serving path
# Only enforce a password when the command actually binds a non-loopback
# socket (i.e. passes --unsafe-bind). `init` and other one-shots skip this.
_needs_pw=0
for _arg in "$@"; do
    if [ "$_arg" = "--unsafe-bind" ]; then
        _needs_pw=1
        break
    fi
done

if [ "$_needs_pw" = "1" ] && [ -z "${REQLORE_PASSWORD_HASH:-}" ]; then
    if [ -f "$HASH_FILE" ]; then
        # Already configured (interactive set-password, or a previous
        # env-seeded run). The persisted hash is the source of truth.
        REQLORE_PASSWORD_HASH="$(cat "$HASH_FILE")"
        export REQLORE_PASSWORD_HASH
        unset REQLORE_PASSWORD 2>/dev/null || true
    elif [ -n "${REQLORE_PASSWORD:-}" ]; then
        # First run with a plaintext password supplied via the environment
        # (typically a .env file). Hash it once, persist the hash, and hand
        # only the hash to reqlore -- the plaintext never touches disk and is
        # dropped from the environment. `docker compose up -d` now works with
        # no separate command.
        _h="$(_hash_password "$REQLORE_PASSWORD")"
        ( umask 077; printf '%s' "$_h" > "$HASH_FILE" )
        chmod 600 "$HASH_FILE" 2>/dev/null || true
        unset _h
        REQLORE_PASSWORD_HASH="$(cat "$HASH_FILE")"
        export REQLORE_PASSWORD_HASH
        unset REQLORE_PASSWORD
        echo "Saved UI password (argon2id hash) to $HASH_FILE for future launches." >&2
    elif _have_tty; then
        # Interactive first run (e.g. `docker compose run`): prompt now.
        echo "No Reqlore UI password is set yet -- let's create one." >&2
        _set_password
        REQLORE_PASSWORD_HASH="$(cat "$HASH_FILE")"
        export REQLORE_PASSWORD_HASH
    else
        cat >&2 <<'EOF'

============================================================
 Reqlore: no UI password has been set yet.

 A password is required because the container binds 0.0.0.0
 internally (needed for Docker's host port-forward).

 Pick ONE of these, then re-run `docker compose up -d`:

 A) Put it in a .env file next to docker-compose.yml, so
    `docker compose up -d` just works with no extra step:

        echo REQLORE_PASSWORD=your-strong-password > .env

 B) Or set it interactively (nothing stored in a file):

        docker compose run --rm reqlore set-password

 Either way it is stored only as an argon2id hash in
 ./data/.reqlore-auth and reused on every later launch. To
 change it later: re-run option B, or delete that file.
============================================================

EOF
        exit 1
    fi
fi

exec reqlore "$@"
