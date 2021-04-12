FROM node:15.11.0-alpine3.13 AS base


FROM base AS graphql-deps-builder

WORKDIR /opt/opencti-build/opencti-graphql
COPY opencti-graphql/package.json opencti-graphql/yarn.lock ./
RUN yarn install --frozen-lockfile --production && yarn cache clean --all


FROM base AS graphql-builder

WORKDIR /opt/opencti-build/opencti-graphql
COPY opencti-graphql/package.json opencti-graphql/yarn.lock ./
RUN yarn install
COPY opencti-graphql /opt/opencti-build/opencti-graphql
RUN yarn run webpack --mode production


FROM base AS front-builder

WORKDIR /opt/opencti-build/opencti-front
COPY opencti-front/package.json opencti-front/yarn.lock ./
RUN yarn install
COPY opencti-front /opt/opencti-build/opencti-front
COPY opencti-graphql/config/schema/opencti.graphql /opt/opencti-build/opencti-graphql/config/schema/opencti.graphql
RUN yarn relay && yarn generate


FROM base AS app

RUN set -ex; \
    apk add --no-cache tini~=0.19 gcc~=10.2 musl-dev~=1.2 python3~=3.8 python3-dev~=3.8; \
    python3 -m ensurepip; \
    rm -rv /usr/lib/python*/ensurepip; \
    pip3 install --no-cache-dir --upgrade pip setuptools wheel; \
    ln -sf python3 /usr/bin/python;
WORKDIR /opt/opencti
COPY opencti-graphql/src/python/requirements.txt ./src/python/requirements.txt
RUN pip3 install --no-cache-dir --requirement ./src/python/requirements.txt
COPY --from=graphql-deps-builder /opt/opencti-build/opencti-graphql/node_modules ./node_modules
COPY --from=graphql-builder /opt/opencti-build/opencti-graphql/build ./build
COPY --from=front-builder /opt/opencti-build/opencti-front/build ./public
COPY opencti-graphql/src ./src
COPY opencti-graphql/config ./config
COPY opencti-graphql/script ./script
ENV PYTHONUNBUFFERED=1
ENV NODE_OPTIONS=--max_old_space_size=8192
ENV NODE_ENV=production

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/index.js"]
