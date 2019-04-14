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

# Chown the application
chown -R ${RUN_USER} /opt/opencti

# Upgrade schema & do migrations
cd /opt/opencti
sudo -H -u ${RUN_USER} npm run schema
TOKEN=`sudo -H -u ${RUN_USER} npm run migrate | grep "Token for user admin:" | awk '{split($0,a,": "); print a[2]}'`
[ -n "$TOKEN" ] && echo $TOKEN > /opt/opencti/shared_config/token

# Start
sudo -H -u ${RUN_USER} node dist/server.js
