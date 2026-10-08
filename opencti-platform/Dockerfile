# syntax=docker/dockerfile:1.28
# Built from the repository root: docker build -f opencti-platform/Dockerfile .
FROM node:22-alpine3.23 AS base


##############################
### Build builder
##############################

FROM base AS builder

# For layer optimisation, start by installing resources not dependant from source code
RUN <<EOT
  set -euxo pipefail

  apk --no-cache add make g++ python3 python3-dev
  npm install -g corepack
EOT

WORKDIR /opt/opencti

COPY .yarnrc.yml package.json yarn.lock ./
COPY patch/ ./patch/
COPY opencti-platform/eslint-plugin-custom-rules/package.json ./opencti-platform/eslint-plugin-custom-rules/
COPY opencti-platform/opencti-front/package.json ./opencti-platform/opencti-front/
COPY opencti-platform/opencti-graphql/package.json ./opencti-platform/opencti-graphql/

ENV YARN_ENABLE_IMMUTABLE_INSTALLS="true"

# uv static binary, pinned by digest; Renovate updates the tag and the digest together. Used by `yarn install:python`
COPY --from=ghcr.io/astral-sh/uv:0.12.9@sha256:8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff /uv /bin/uv


##############################
### Build back
##############################

FROM builder AS builder-back

# TAG_VERSION used to generate connector manifest on a tag during yarn build. Default to rolling manifest
ARG TAG_VERSION
ENV TAG_VERSION="${TAG_VERSION}"

RUN yarn workspaces focus opencti-graphql

WORKDIR /opt/opencti/opencti-platform/opencti-graphql

# Copy all remaining sources
COPY opencti-platform/opencti-graphql/ ./
RUN yarn build:prod

# uv workspace metadata and pycti of the same commit: the backend tests run `yarn install:python` in this stage's image
COPY pyproject.toml uv.lock /opt/opencti/
COPY client-python/ /opt/opencti/client-python/
COPY opencti-worker/pyproject.toml /opt/opencti/opencti-worker/

##############################
### Build front
##############################

FROM builder AS builder-front

RUN yarn workspaces focus opencti-front

WORKDIR /opt/opencti/opencti-platform/opencti-front

# Copy all remaining sources and build
COPY opencti-platform/opencti-front/ ./
RUN yarn build

##############################
### Build Python runtime
##############################

FROM base AS builder-python

RUN apk --no-cache add python3

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
    uv sync --locked --no-dev --no-editable --no-install-workspace --package opencti-platform-python

# project layer: pycti of the same commit
COPY pyproject.toml uv.lock ./
COPY client-python/ ./client-python/
COPY opencti-worker/pyproject.toml ./opencti-worker/pyproject.toml
COPY opencti-platform/opencti-graphql/src/python/pyproject.toml ./opencti-platform/opencti-graphql/src/python/pyproject.toml
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=opencti-platform/opencti-graphql/src/python/link_site_packages.py,target=/tmp/link_site_packages.py <<EOT
  set -euxo pipefail

  uv sync --locked --no-dev --no-editable --package opencti-platform-python
  # stable path to the site-packages, whatever the Python version of the image
  .venv/bin/python /tmp/link_site_packages.py
EOT

##############################
### Build production image
##############################

FROM base AS app

RUN <<EOT
  set -euxo pipefail

  apk --no-cache upgrade
  apk --no-cache add tini python3 python3-dev
  rm /var/log/apk.log
EOT

WORKDIR /opt/opencti

COPY --from=builder-back /opt/opencti/opencti-platform/opencti-graphql/build/ ./build/
COPY --from=builder-back /opt/opencti/opencti-platform/opencti-graphql/config/ ./config/
COPY --from=builder-back /opt/opencti/opencti-platform/opencti-graphql/src/python/runtime/ ./src/python/runtime/
COPY --from=builder-back /opt/opencti/opencti-platform/opencti-graphql/static/ ./static/
COPY --from=builder-front /opt/opencti/opencti-platform/opencti-front/dist/ ./public/
# Python runtime dependencies: virtual environment only, no uv, no pip
COPY --from=builder-python /opt/opencti/.venv/ ./.venv/

ENV PATH="/opt/opencti/.venv/bin:$PATH"
ENV APP__PYTHON_EXECUTION_VENV="/opt/opencti/.venv/site-packages"
ENV PYTHONUNBUFFERED="1"
ENV NODE_OPTIONS="--max_old_space_size=12288"
ENV NODE_ENV="production"

RUN <<EOT
  set -euxo pipefail

  install -m 0777 -d '/opt/opencti/logs'
  install -m 0777 -d '/opt/opencti/telemetry'
  install -m 0777 -d '/opt/opencti/.support'
EOT

VOLUME ["/opt/opencti/logs", "/opt/opencti/telemetry", "/opt/opencti/.support"]

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/back.mjs"]
