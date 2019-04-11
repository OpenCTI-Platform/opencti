# Use the official Docker Hub Ubuntu 18.04 base image
FROM ubuntu:18.04

# Update the base image
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade

# Setup install environment and OpenCTI dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install nodejs npm sudo rsyslog wget

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh 
EXPOSE 4000/tcp
ENTRYPOINT ["/entrypoint.sh"]
