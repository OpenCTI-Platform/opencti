# syntax=docker/dockerfile:1.28
# Built from the repository root: docker build -f opencti-worker/Dockerfile .
FROM python:3.12-alpine AS builder

# uv static binary, pinned by digest; Renovate updates the tag and the digest together
COPY --from=ghcr.io/astral-sh/uv:0.12.9@sha256:8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff /uv /bin/uv

# faster startup, cache mount compatibility, use the image's Python
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /opt/opencti

# dependency layer: only invalidated when the workspace metadata or uv.lock change
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    --mount=type=bind,source=client-python/pyproject.toml,target=client-python/pyproject.toml \
    --mount=type=bind,source=opencti-worker/pyproject.toml,target=opencti-worker/pyproject.toml \
    --mount=type=bind,source=opencti-platform/opencti-graphql/src/python/pyproject.toml,target=opencti-platform/opencti-graphql/src/python/pyproject.toml \
    uv sync --locked --no-dev --no-editable --no-install-workspace --package opencti-worker

# project layer: pycti of the same commit
COPY pyproject.toml uv.lock ./
COPY client-python/ ./client-python/
COPY opencti-worker/pyproject.toml ./opencti-worker/pyproject.toml
COPY opencti-platform/opencti-graphql/src/python/pyproject.toml ./opencti-platform/opencti-graphql/src/python/pyproject.toml
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable --package opencti-worker

FROM python:3.12-alpine

# security: system packages up to date, non-root user, no uv, no pip, no build tooling in the runtime image
RUN <<EOT
    set -euxo pipefail

    apk --no-cache upgrade
    rm -f /var/log/apk.log
    python3 -m pip uninstall --yes --root-user-action=ignore pip
    addgroup -S opencti
    adduser -S -H -G opencti -h /opt/opencti-worker opencti
EOT
# owned by root: the worker user can read and run them, not change them
COPY --from=builder /opt/opencti/.venv /opt/opencti/.venv
COPY opencti-worker/src /opt/opencti-worker
ENV PATH="/opt/opencti/.venv/bin:$PATH"
USER opencti
WORKDIR /opt/opencti-worker

ENTRYPOINT ["python3"]
CMD ["worker.py"]
