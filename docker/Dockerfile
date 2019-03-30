# Use the official Docker Hub Ubuntu 18.04 base image
FROM ubuntu:18.04

# Update the base image
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade

# Setup install environment and OpenEx dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install apache2 libapache2-mod-php7.2 sudo rsyslog wget openjdk-8-jre

# Enable the Apache rewrite module
RUN a2enmod rewrite
RUN sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf

# Install PHP dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install php7.2-cli php7.2-xml php7.2-pgsql php7.2-ldap php7.2-json php7.2-curl composer

# Download archive
RUN mkdir /var/openex
RUN wget -O /var/openex/openex.tar.gz http://releases.openex.io/openex-release-201810.tar.gz
RUN cd /var/openex && tar xvfz /var/openex/openex.tar.gz

# Configure the app
COPY parameters.yml /var/openex/openex-app/app/config/
RUN sed -i -e "s/SECRET_TO_REPLACE/`date +%s | sha256sum | base64 | head -c 40`/g" /var/openex/openex-app/app/config/parameters.yml

# Create symlink
RUN rm -Rf /var/www/html && ln -s /var/openex/openex-app/web /var/www/html

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
VOLUME /var/openex/openex-app/app/files
VOLUME /var/openex/openex-worker/openex
EXPOSE 80/tcp
ENTRYPOINT ["/entrypoint.sh"]