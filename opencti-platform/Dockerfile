FROM node:16.6.0-alpine3.14 AS base

RUN corepack enable

FROM base AS graphql-deps-builder
WORKDIR /opt/opencti-build/opencti-graphql
COPY opencti-graphql/package.json opencti-graphql/yarn.lock ./
RUN yarn install --network-timeout 300000 --frozen-lockfile --production && yarn cache clean --all


FROM base AS graphql-builder
WORKDIR /opt/opencti-build/opencti-graphql
COPY opencti-graphql/package.json opencti-graphql/yarn.lock ./
RUN yarn install --network-timeout 300000
COPY opencti-graphql /opt/opencti-build/opencti-graphql
RUN yarn run webpack --mode production
RUN yarn schema-compile


FROM base AS front-builder
WORKDIR /opt/opencti-build/opencti-front
COPY opencti-front/package.json opencti-front/yarn.lock opencti-front/.yarnrc.yml ./
COPY opencti-front/.yarn ./.yarn
RUN yarn install --network-timeout 300000
COPY opencti-front /opt/opencti-build/opencti-front
COPY --from=graphql-builder /opt/opencti-build/opencti-graphql/config/schema/compiled.graphql /opt/opencti-build/opencti-graphql/config/schema/compiled.graphql
RUN yarn relay && yarn generate


FROM base AS app
RUN set -ex; \
    apk add --no-cache git tini gcc musl-dev python3 python3-dev postfix postfix-pcre; \
    python3 -m ensurepip; \
    rm -rv /usr/lib/python*/ensurepip; \
    pip3 install --no-cache-dir --upgrade pip setuptools wheel; \
    ln -sf python3 /usr/bin/python;
WORKDIR /opt/opencti
COPY opencti-graphql/src/python/requirements.txt ./src/python/requirements.txt
RUN pip3 install --no-cache-dir --requirement ./src/python/requirements.txt
RUN pip3 install --upgrade --force --no-cache-dir git+https://github.com/OpenCTI-Platform/client-python@master
RUN apk del git python3-dev gcc musl-dev
COPY --from=graphql-deps-builder /opt/opencti-build/opencti-graphql/node_modules ./node_modules
COPY --from=graphql-builder /opt/opencti-build/opencti-graphql/build ./build
COPY --from=front-builder /opt/opencti-build/opencti-front/build ./public
COPY opencti-graphql/src ./src
COPY opencti-graphql/config ./config
COPY opencti-graphql/script ./script
ENV PYTHONUNBUFFERED=1
ENV NODE_OPTIONS=--max_old_space_size=8192
ENV NODE_ENV=production

RUN rm /opt/opencti/config/schema/compiled.graphql

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/index.js"]
