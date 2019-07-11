# Use the official Docker Hub Ubuntu 18.04 base image
FROM ubuntu:18.04

# Update the base image
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade

# Node v11
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install curl rsyslog wget netcat
RUN curl -sL https://deb.nodesource.com/setup_11.x | bash -
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs

# Yarn
RUN curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
RUN echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y install yarn

# Copy work files
COPY opencti-front /opt/opencti-build/opencti-front
COPY opencti-graphql /opt/opencti-build/opencti-graphql

# Build frontend
RUN cd /opt/opencti-build/opencti-front && yarn install && yarn build

# Build GraphQL API
RUN cd /opt/opencti-build/opencti-graphql && yarn install && yarn build
RUN mv /opt/opencti-build/opencti-graphql /opt/opencti

# Clean
RUN rm -Rf /opt/opencti-build

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh 
EXPOSE 4000/tcp
ENTRYPOINT ["/entrypoint.sh"]