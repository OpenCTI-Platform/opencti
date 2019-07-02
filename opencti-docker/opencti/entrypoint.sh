#!/bin/sh

# Start log
/etc/init.d/rsyslog start

# Wait launching
while ! nc -z ${ELASTICSEARCH__HOSTNAME} 9200; do
  echo "Waiting ElasticSearch to launch..."
  sleep 2
done
while ! nc -z ${GRAKN__HOSTNAME} 48555; do
  echo "Waiting Grakn to launch..."
  sleep 2
done
while ! nc -z ${REDIS__HOSTNAME} 6379; do
  echo "Waiting Redis to launch..."
  sleep 2
done
while ! nc -z ${RABBITMQ__HOSTNAME} 5672; do
  echo "Waiting RabbitMQ to launch..."
  sleep 2
done

# Upgrade schema & do migrations
cd /opt/opencti
npm run schema
TOKEN=`npm run migrate | grep "Token for user admin:" | awk '{split($0,a,": "); print a[2]}'`
[ -n "$TOKEN" ] && echo $TOKEN > /opt/opencti/shared_config/token

# Start
node dist/server.js
