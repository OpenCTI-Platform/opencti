FROM node:24-alpine AS base

RUN corepack enable

FROM base AS graphql-deps-builder

WORKDIR /opt/opencti-build/opencti-graphql
COPY opencti-graphql/package.json opencti-graphql/yarn.lock ../.yarnrc.yml ./
COPY opencti-graphql/patch ./patch
RUN set -ex; \
    apk add --no-cache git tini gcc g++ make musl-dev cargo python3 python3-dev postfix postfix-pcre \
    && npm install -g node-gyp \
    && yarn install --immutable && yarn cache clean --all


FROM base AS graphql-builder

WORKDIR /opt/opencti-build/opencti-graphql
COPY opencti-graphql/package.json opencti-graphql/yarn.lock ../.yarnrc.yml ./
COPY opencti-graphql/patch ./patch
RUN set -ex; \
    apk add --no-cache git tini gcc g++ make musl-dev cargo python3 python3-dev postfix postfix-pcre \
    && rm -f /usr/lib/python3.11/EXTERNALLY-MANAGED \
    && rm -f /usr/lib/python3.12/EXTERNALLY-MANAGED \
    && npm install -g node-gyp \
    && yarn install
COPY opencti-graphql /opt/opencti-build/opencti-graphql
RUN yarn build:prod


FROM base AS front-builder

WORKDIR /opt/opencti-build/opencti-front

COPY opencti-front/package.json opencti-front/yarn.lock ../.yarnrc.yml ./
COPY opencti-front/.yarn ./.yarn
COPY opencti-front/packages ./packages
RUN set -ex; \
    apk add --no-cache git tini gcc g++ make musl-dev cargo python3 python3-dev postfix postfix-pcre \
    && rm -f /usr/lib/python3.11/EXTERNALLY-MANAGED \
    && rm -f /usr/lib/python3.12/EXTERNALLY-MANAGED \
    && npm install -g node-gyp \
&& yarn install

COPY opencti-front /opt/opencti-build/opencti-front
COPY opencti-graphql/config/schema/opencti.graphql /opt/opencti-build/opencti-graphql/config/schema/opencti.graphql

RUN yarn build:standalone


FROM base AS app

RUN set -ex; \
    apk add --no-cache git tini gcc g++ make musl-dev cargo python3 python3-dev postfix postfix-pcre \
    && rm -f /usr/lib/python3.11/EXTERNALLY-MANAGED \
    && rm -f /usr/lib/python3.12/EXTERNALLY-MANAGED \
    && python3 -m ensurepip \
    && rm -rv /usr/lib/python*/ensurepip \
    && pip3 install --no-cache-dir --upgrade pip setuptools wheel \
    && ln -sf python3 /usr/bin/python
WORKDIR /opt/opencti

COPY opencti-graphql/src/python/requirements.txt ./src/python/requirements.txt

RUN pip3 install --no-cache-dir --requirement ./src/python/requirements.txt \
    && pip3 install \
        --no-cache-dir \
        --upgrade \
        --force 'git+https://github.com/OpenCTI-Platform/opencti@master#subdirectory=client-python' \
    && apk del git gcc musl-dev

COPY --from=graphql-deps-builder /opt/opencti-build/opencti-graphql/node_modules ./node_modules
COPY --from=graphql-builder /opt/opencti-build/opencti-graphql/build ./build
COPY --from=graphql-builder /opt/opencti-build/opencti-graphql/static ./static
COPY --from=front-builder /opt/opencti-build/opencti-front/builder/prod/build ./public
COPY opencti-graphql/src ./src
COPY opencti-graphql/config ./config
COPY opencti-graphql/script ./script

ENV PYTHONUNBUFFERED=1
ENV NODE_OPTIONS=--max_old_space_size=12288
ENV NODE_ENV=production

RUN set -ex; \
    install -m 0777 -d '/opt/opencti/logs' \
    && install -m 0777 -d '/opt/opencti/telemetry' \
    && install -m 0777 -d '/opt/opencti/.support'

VOLUME ["/opt/opencti/logs", "/opt/opencti/telemetry", "/opt/opencti/.support"]

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/back.js"]