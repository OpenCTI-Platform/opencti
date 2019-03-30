#!/bin/sh

# Env vars
export APACHE_RUN_USER=${RUN_USER}
export APACHE_RUN_GROUP=${RUN_GROUP}
export APACHE_LOCK_DIR=/var/lock/apache2
export APACHE_PID_FILE=/var/run/apache2/apache2.pid
export APACHE_RUN_DIR=/var/run/apache2
export APACHE_LOG_DIR=/var/log/apache2

# Chown application
chown -R ${RUN_USER}:${RUN_GROUP} /var/openex

# Start log
/etc/init.d/rsyslog start

# Doctrine migration & creation
cd /var/openex
sudo -H -u ${RUN_USER} php bin/console doctrine:migrations:migrate -n

# Start Worker
sudo -H -u ${RUN_USER} /var/openex/openex-worker/bin/start &

# Start Apache2
exec apache2 -DNO_DETACH -k start
