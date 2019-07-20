# Use the official Docker Hub Ubuntu 18.04 base image
FROM ubuntu:19.04

# Update the base image
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade

# Setup install environment and OpenCTI dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3 python3-pip curl rsyslog wget netcat locales

# Set the locale
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8 

# Copy the worker
COPY src /opt/opencti-worker

# Install Python modules
RUN cd /opt/opencti-worker && pip3 install -r requirements.txt

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh 
ENTRYPOINT ["/entrypoint.sh"]
