# Use the official Docker Hub Ubuntu 18.04 base image
FROM ubuntu:18.04

# Update the base image
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade

# Setup install environment and OpenCTI dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3 python3-pip curl rsyslog wget netcat locales

# Download archive
RUN wget -O /opt/opencti.tar.gz https://releases.opencti.io/opencti-REPLACE_DATE.tar.gz
RUN cd /opt && tar xvfz opencti.tar.gz

# Set the locale
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8 

# Prepare configuration
RUN cd /opt/opencti/integration && rm -f config.yml && ln -s /opt/opencti/shared_config/config_integration.yml config.yml

# Install Python modules
RUN cd /opt/opencti/integration && pip3 install -r requirements.txt

# Install Python modules of each connectors
RUN cd /opt/opencti/integration && find connectors -name requirements.txt -exec pip3 install -r {} \;

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh 
ENTRYPOINT ["/entrypoint.sh"]
