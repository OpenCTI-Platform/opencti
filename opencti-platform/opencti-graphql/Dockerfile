FROM node:16-alpine AS base

RUN set -ex; \
    corepack enable; \
    apk add --no-cache git tini gcc musl-dev python3 python3-dev postfix postfix-pcre make g++; \
    python3 -m ensurepip; \
    rm -rv /usr/lib/python*/ensurepip; \
    pip3 install --no-cache-dir --upgrade pip setuptools wheel; \
    ln -sf python3 /usr/bin/python;

FROM base AS graphql-builder
WORKDIR /opt/opencti-build/opencti-graphql
COPY . .
#Missing node-gyp as a dep?  Usage Error: Couldn't find a script name "node-gyp" in the top-level (used by deasync@npm:0.1.28)
#I've seen it build before.
RUN yarn add node-gyp
#Can run yarn test after yarn install here:
RUN yarn install --check-cache --inline-builds --network-timeout 300000 --immutable && yarn cache clean --all
RUN yarn run webpack --mode production
RUN yarn schema-compile

FROM base AS app
WORKDIR /opt/opencti
COPY ./src/python/requirements.txt ./src/python/requirements.txt
RUN pip3 install --no-cache-dir --requirement ./src/python/requirements.txt
RUN pip3 install --upgrade --force --no-cache-dir git+https://github.com/OpenCTI-Platform/client-python@master
RUN apk del git python3-dev gcc musl-dev make g++
COPY --from=graphql-builder /opt/opencti-build/opencti-graphql/node_modules ./node_modules
COPY --from=graphql-builder /opt/opencti-build/opencti-graphql/build ./build
COPY ./src ./src
COPY ./config ./config
COPY ./script ./script
ENV PYTHONUNBUFFERED=1
ENV NODE_OPTIONS=--max_old_space_size=8192
ENV NODE_ENV=production

RUN rm -f /opt/opencti/config/schema/compiled.graphql

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/index.js"]
