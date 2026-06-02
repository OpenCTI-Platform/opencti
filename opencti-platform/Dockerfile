# syntax=docker/dockerfile:1.7
FROM node:22-alpine3.23 AS base


##############################
### Build builder
##############################

FROM base AS builder

# For layer optimisation, start by installing resources not dependant from source code
RUN <<EOT
  set -euxo pipefail

  apk --no-cache add make g++ python3 python3-dev libmagic
  rm -f /usr/lib/python*/EXTERNALLY-MANAGED
  python3 -m ensurepip
  npm install -g corepack
EOT

COPY .yarnrc.yml /opt/opencti/


##############################
### Build back
##############################

FROM builder AS builder-back

# TAG_VERSION used to generate connector manifest on a tag during yarn build. Default to rolling manifest
ARG TAG_VERSION
ENV TAG_VERSION="${TAG_VERSION}"

WORKDIR /opt/opencti/opencti-graphql

# Copy sources necessary for install (preserve cache if no dependency changes)
COPY opencti-graphql/package.json opencti-graphql/yarn.lock ./
COPY opencti-graphql/patch/ ./patch/

RUN yarn install --immutable

# Copy all remaining sources
COPY opencti-graphql/ ./
RUN yarn build:prod

##############################
### Build front
##############################

FROM builder AS builder-front
WORKDIR /opt/opencti/opencti-front

# Copy sources necessary for install (preserve cache if no dependency changes)
COPY opencti-front/package.json opencti-front/yarn.lock ./
COPY opencti-front/packages/ ./packages/

RUN yarn install --immutable

# Copy all remaining sources and build
COPY opencti-front/ ./
RUN <<EOT
  set -euxo pipefail

  mkdir -p ../opencti-graphql/public; \
  yarn build
EOT

##############################
### Build production image
##############################

FROM base AS app

RUN <<EOT
  set -euxo pipefail

  apk --no-cache add tini python3 python3-dev libmagic
  rm /var/log/apk.log
  rm -f /usr/lib/python*/EXTERNALLY-MANAGED
  python3 -m ensurepip
EOT

RUN --mount=type=bind,source=opencti-graphql/src/python/requirements.txt,target=/opt/opencti/src/python/requirements.txt <<EOT
  set -euxo pipefail

  apk --no-cache add -t .pip_deps git
  pip3 install --no-cache-dir --requirement /opt/opencti/src/python/requirements.txt
  apk del .pip_deps
  rm /var/log/apk.log
EOT

WORKDIR /opt/opencti

COPY --from=builder-back /opt/opencti/opencti-graphql/build/ ./build/
COPY --from=builder-back /opt/opencti/opencti-graphql/config/ ./config/
COPY --from=builder-back /opt/opencti/opencti-graphql/src/python/ ./src/python/
COPY --from=builder-back /opt/opencti/opencti-graphql/static/ ./static/
COPY --from=builder-front /opt/opencti/opencti-graphql/public/ ./public/

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
CMD ["node", "build/back.js"]
