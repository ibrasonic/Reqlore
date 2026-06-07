# --- Build stage ---------------------------------------------------------------
# Builds the wheel in an isolated layer so the runtime image stays small and
# does not contain build toolchain or .git history.
FROM python:3.12-slim AS build

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
COPY weblore ./weblore

RUN pip install --upgrade pip build \
 && python -m build --wheel --outdir /dist


# --- Runtime stage -------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    WEBLORE_DATA=/data

# Runtime libs only (no compilers).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libxml2 libxslt1.1 libffi8 ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1000 weblore \
 && useradd  --system --uid 1000 --gid weblore --home /home/weblore --create-home weblore \
 && mkdir -p /data \
 && chown -R weblore:weblore /data /home/weblore

# Install the wheel + the most useful optional extras for general-purpose use.
# Skip the dev / a11y extras (those are CI-only).
COPY --from=build /dist/*.whl /tmp/
RUN pip install --upgrade pip \
 && pip install /tmp/*.whl[report,yaml,schedule] \
 && rm -rf /tmp/*.whl /root/.cache

USER weblore
WORKDIR /data
VOLUME ["/data"]

# UI = 8787, MITM proxy = 8080. Host-side `-p 127.0.0.1:<port>:<port>` keeps
# the listener on loopback even though we have to bind 0.0.0.0 internally.
EXPOSE 8787 8080

# tini reaps zombies (helps the proxy + UI sub-processes shut down cleanly).
ENTRYPOINT ["/usr/bin/tini", "--", "weblore"]
CMD ["--help"]
