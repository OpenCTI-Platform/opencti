#!/bin/sh

# Start log
/etc/init.d/rsyslog start

# Upgrade schema & do migrations
cd /opt/opencti
sudo -H -u ${RUN_USER} npm run schema
sudo -H -u ${RUN_USER} npm run migrate

# Start
sudo -H -u ${RUN_USER} node dist/server.js
