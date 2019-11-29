FROM node:12.13.1-alpine

# Copy work files
COPY opencti-front /opt/opencti-build/opencti-front
COPY opencti-graphql /opt/opencti-build/opencti-graphql
COPY entrypoint.sh /

# Install Python
RUN apk add --update \
    python \
    python-dev \
    py-pip \
    build-base

# Build frontend && GraphQL API
# hadolint ignore=DL3003
RUN BUILD_OPENCTI=noninteractive \
    cd /opt/opencti-build/opencti-front && \
	  yarn install && \
	  yarn build && \
	  yarn cache clean && \
	  cd /opt/opencti-build/opencti-graphql && \
	  yarn install && \
	  yarn build && \
	  yarn cache clean && \
	  mv /opt/opencti-build/opencti-graphql /opt/opencti && \
	  rm -rf /opt/opencti-build

# Expose and entrypoint
RUN chmod +x /entrypoint.sh
EXPOSE 4000/tcp
ENTRYPOINT ["/entrypoint.sh"]
