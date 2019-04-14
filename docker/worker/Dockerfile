# Use the official Docker Hub Ubuntu 18.04 base image
FROM ubuntu:18.04

# Update the base image
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade

# Setup install environment and OpenCTI dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3 python3-pip curl sudo rsyslog wget netcat

# Download archive
RUN wget -O /opt/opencti.tar.gz https://releases.opencti.io/opencti-release-201904.tar.gz
RUN cd /opt && tar xvfz opencti.tar.gz

# Prepare configuration
RUN cd /opt/opencti/worker && ln -s /opt/opencti/shared_config/config.yml .

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh 
ENTRYPOINT ["/entrypoint.sh"]
