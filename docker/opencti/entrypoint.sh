#!/bin/sh

# Start log
/etc/init.d/rsyslog start

# Wait launching
echo "Waiting ElasticSearch to launch..."
while ! nc -z elasticsearch 9200; do   
  sleep 0.1
done
echo "Waiting Grakn to launch..."
while ! nc -z grakn 48555; do   
  sleep 0.1
done

# Upgrade schema & do migrations
cd /opt/opencti
sudo -H -u ${RUN_USER} npm run schema
sudo -H -u ${RUN_USER} npm run migrate

# Start
sudo -H -u ${RUN_USER} node dist/server.js
