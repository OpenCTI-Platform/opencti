FROM node:16-alpine AS base

RUN corepack enable

FROM base AS graphql-deps-builder

WORKDIR /opt/opencti-build/opencti-graphql
COPY opencti-graphql/package.json opencti-graphql/yarn.lock opencti-graphql/.yarnrc.yml ./
COPY opencti-graphql/.yarn ./.yarn
COPY opencti-graphql/patch ./patch
RUN yarn install --frozen-lockfile && yarn cache clean --all


FROM base AS graphql-builder

WORKDIR /opt/opencti-build/opencti-graphql
COPY opencti-graphql/package.json opencti-graphql/yarn.lock opencti-graphql/.yarnrc.yml ./
COPY opencti-graphql/.yarn ./.yarn
COPY opencti-graphql/patch ./patch
RUN yarn install
COPY opencti-graphql /opt/opencti-build/opencti-graphql
RUN yarn build:prod


FROM base AS front-builder

WORKDIR /opt/opencti-build/opencti-front

COPY opencti-front/package.json opencti-front/yarn.lock opencti-front/.yarnrc.yml ./
COPY opencti-front/.yarn ./.yarn
COPY opencti-front/patch ./patch

RUN yarn install

COPY opencti-front /opt/opencti-build/opencti-front
COPY opencti-graphql/config/schema/opencti.graphql /opt/opencti-build/opencti-graphql/config/schema/opencti.graphql

RUN yarn build:standalone


FROM base AS app

RUN set -ex \
    ; apk add --no-cache git tini gcc musl-dev python3 python3-dev postfix postfix-pcre \
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
        --force 'git+https://github.com/OpenCTI-Platform/client-python@master' \
    && apk del git python3-dev gcc musl-dev

COPY --from=graphql-deps-builder /opt/opencti-build/opencti-graphql/node_modules ./node_modules
COPY --from=graphql-builder /opt/opencti-build/opencti-graphql/build ./build
COPY --from=graphql-builder /opt/opencti-build/opencti-graphql/static ./static
COPY --from=front-builder /opt/opencti-build/opencti-front/builder/prod/build ./public
COPY opencti-graphql/src ./src
COPY opencti-graphql/config ./config
COPY opencti-graphql/script ./script

ARG UID=10000
ARG GID=10001
ARG USERNAME="_opencti"

ENV PYTHONUNBUFFERED=1
ENV NODE_OPTIONS=--max_old_space_size=12288
ENV NODE_ENV=production

RUN set -ex \
    ; addgroup -g "${GID}" -S "${USERNAME}" \
    && adduser \
        -h /opt/opencti \
        -g "OpenCTI privsep user" \
        -s "/sbin/nologin" \
        -G "${USERNAME}" \
        -S \
        -u "${UID}" \
        "${USERNAME}" \
    && install -o "${UID}" -g "${GID}" -m 0750 -d '/opt/opencti/logs'

VOLUME ["/opt/opencti/logs"]

USER "${USERNAME}"

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/index.js"]
