FROM node:22-bookworm-slim AS base

RUN corepack enable

RUN apt-get update && apt-get install -y \
    git \
    tini \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    cargo \
    postfix \
    wget \
 && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------

# GraphQL dependencies

# ------------------------------------------------------------

FROM base AS graphql-deps-builder

WORKDIR /opt/opencti-build/opencti-graphql

COPY opencti-graphql/package.json opencti-graphql/yarn.lock ../.yarnrc.yml ./
COPY opencti-graphql/patch ./patch

RUN npm install -g node-gyp && yarn install --immutable && yarn cache clean --all

# ------------------------------------------------------------

# GraphQL build

# ------------------------------------------------------------

FROM base AS graphql-builder

WORKDIR /opt/opencti-build/opencti-graphql

COPY opencti-graphql/package.json opencti-graphql/yarn.lock ../.yarnrc.yml ./
COPY opencti-graphql/patch ./patch

RUN npm install -g node-gyp && yarn install

COPY opencti-graphql .

RUN yarn build:prod

# ------------------------------------------------------------

# Front build

# ------------------------------------------------------------

FROM base AS front-builder

WORKDIR /opt/opencti-build/opencti-front

COPY opencti-front/package.json opencti-front/yarn.lock ../.yarnrc.yml ./
COPY opencti-front/packages ./packages

RUN npm install -g node-gyp && yarn install

COPY opencti-front .

COPY opencti-graphql/config/schema/opencti.graphql /opt/opencti-build/opencti-graphql/config/schema/opencti.graphql

RUN yarn build:standalone

# ------------------------------------------------------------

# Application

# ------------------------------------------------------------

FROM base AS app

RUN python3 -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV NODE_OPTIONS=--max_old_space_size=12288
ENV NODE_ENV=production

WORKDIR /opt/opencti

COPY opencti-graphql/src/python/requirements.txt ./src/python/requirements.txt

RUN pip install --upgrade pip setuptools wheel

RUN pip install --no-cache-dir -r ./src/python/requirements.txt && pip install --no-cache-dir --upgrade "git+https://github.com/OpenCTI-Platform/opencti@master#subdirectory=client-python"

COPY --from=graphql-deps-builder /opt/opencti-build/opencti-graphql/node_modules ./node_modules
COPY --from=graphql-builder /opt/opencti-build/opencti-graphql/build ./build
COPY --from=graphql-builder /opt/opencti-build/opencti-graphql/static ./static
COPY --from=front-builder /opt/opencti-build/opencti-front/builder/prod/build ./public

COPY opencti-graphql/src ./src
COPY opencti-graphql/config ./config
COPY opencti-graphql/script ./script

RUN install -m 0777 -d /opt/opencti/logs && install -m 0777 -d /opt/opencti/telemetry && install -m 0777 -d /opt/opencti/.support

VOLUME ["/opt/opencti/logs", "/opt/opencti/telemetry", "/opt/opencti/.support"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "build/back.js"]
