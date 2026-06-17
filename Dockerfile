# --- Build stage ---------------------------------------------------------------
# Builds the wheel in an isolated layer so the runtime image stays small and
# does not contain build toolchain or .git history.
#
# L-11: pin to a specific image digest instead of the floating ``3.12-slim``
# tag so a compromised or maliciously re-pushed base image cannot replace
# the build root we resolved at audit time. Bump this digest with every
# Debian / CPython security release; ``docker buildx imagetools inspect
# python:3.12-slim`` prints the current value.
FROM python:3.12-slim@sha256:c2d8472b831337ab296a8ce652e1ba786e9e3034fc445dc58b50a7f5251f0003 AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /src

# Toolchain needed by a few wheels (lxml, cryptography, argon2-cffi) on slim.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential libffi-dev libssl-dev libxml2-dev libxslt-dev \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY reqlore ./reqlore

RUN pip install --upgrade pip build \
 && python -m build --wheel --outdir /dist


# --- Runtime stage -------------------------------------------------------------
# Same digest pin as the build stage -- see L-11 note above.
FROM python:3.12-slim@sha256:c2d8472b831337ab296a8ce652e1ba786e9e3034fc445dc58b50a7f5251f0003 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    REQLORE_DATA=/data

# Runtime libs only (no compilers).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libxml2 libxslt1.1 libffi8 ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1000 reqlore \
 && useradd  --system --uid 1000 --gid reqlore --home /home/reqlore --create-home reqlore \
 && mkdir -p /data \
 && chown -R reqlore:reqlore /data /home/reqlore

# Install the wheel + the most useful optional extras for general-purpose use.
# Skip the dev / a11y extras (those are CI-only).
# Note: we can't write `pip install /tmp/*.whl[report,yaml,schedule]` because
# `sh` interprets `[...]` as a glob character class, not as pip's extras
# syntax. Install the wheel first to register `reqlore` on PyPI's local
# resolver, then ask pip again *by package name* with the extras.
COPY --from=build /dist/*.whl /tmp/
RUN pip install --upgrade pip \
 && pip install /tmp/*.whl \
 && pip install "reqlore[report,yaml,schedule]" \
 && rm -rf /tmp/*.whl /root/.cache

USER reqlore
WORKDIR /data
VOLUME ["/data"]

# UI = 8787, MITM proxy = 8080. Host-side `-p 127.0.0.1:<port>:<port>` keeps
# the listener on loopback even though we have to bind 0.0.0.0 internally.
EXPOSE 8787 8080

# tini reaps zombies (helps the proxy + UI sub-processes shut down cleanly).
ENTRYPOINT ["/usr/bin/tini", "--", "reqlore"]
CMD ["--help"]
