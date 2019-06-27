# Use the official Docker Hub Ubuntu 18.04 base image
FROM ubuntu:18.04

# Update the base image
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade

# Node v11
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install curl sudo rsyslog wget netcat
RUN curl -sL https://deb.nodesource.com/setup_11.x | sudo -E bash -
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs

# Download archive
RUN wget -O /opt/opencti.tar.gz https://releases.opencti.io/opencti-20190628.tar.gz
RUN cd /opt && tar xvfz opencti.tar.gz

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh 
EXPOSE 4000/tcp
ENTRYPOINT ["/entrypoint.sh"]
