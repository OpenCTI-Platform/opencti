FROM node:12.13.1-alpine

# Copy work files
COPY opencti-front /opt/opencti-build/opencti-front
COPY opencti-graphql /opt/opencti-build/opencti-graphql
COPY entrypoint.sh /

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1

# Install Python
RUN apk add --update \
    python3 \
    python3-dev \
    py-pip \
    build-base

# Install Python
RUN echo "**** install Python ****" && \
    apk add --no-cache python3 && \
    echo "**** install pip ****" && \
    python3 -m ensurepip && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools wheel

# Build frontend && GraphQL API
# hadolint ignore=DL3003
RUN BUILD_OPENCTI=noninteractive \
    echo "**** install opencti ****" && \
    cd /opt/opencti-build/opencti-front && \
	  yarn install && \
	  yarn build && \
	  yarn cache clean && \
	  cd /opt/opencti-build/opencti-graphql && \
	  yarn install && \
	  yarn build && \
	  yarn cache clean && \
	  mv /opt/opencti-build/opencti-graphql /opt/opencti && \
	  rm -rf /opt/opencti-build && \
      apk del build-base python3-dev

# Expose and entrypoint
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
