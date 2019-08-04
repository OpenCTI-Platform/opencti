#!/bin/bash

# Start log
/etc/init.d/rsyslog start

# Extract ElasticSearch information
proto="$(echo ${ELASTICSEARCH__URL} | grep :// | sed -e's,^\(.*://\).*,\1,g')"
url="$(echo ${ELASTICSEARCH__URL/$proto/})"
hostport="$(echo ${url/$user@/} | cut -d/ -f1)"
ELASTICSEARCH__HOSTNAME="$(echo $hostport | sed -e 's,:.*,,g')"
ELASTICSEARCH__PORT="$(echo $hostport | sed -e 's,^.*:,:,g' -e 's,.*:\([0-9]*\).*,\1,g' -e 's,[^0-9],,g')"
[ -z "$ELASTICSEARCH__PORT" ] && ELASTICSEARCH__PORT=80

# Wait launching
while ! nc -z ${ELASTICSEARCH__HOSTNAME} ${ELASTICSEARCH__PORT}; do
  echo "Waiting ElasticSearch to launch..."
  sleep 2
done
while ! nc -z ${GRAKN__HOSTNAME} ${GRAKN__PORT}; do
  echo "Waiting Grakn to launch..."
  sleep 2
done
while ! nc -z ${REDIS__HOSTNAME} ${REDIS__PORT}; do
  echo "Waiting Redis to launch..."
  sleep 2
done
while ! nc -z ${RABBITMQ__HOSTNAME} ${RABBITMQ__PORT}; do
  echo "Waiting RabbitMQ to launch..."
  sleep 2
done

# Correct working directory
cd /opt/opencti

# Upgrade schema & do migrations
npm run schema
npm run migrate

# Start
node dist/server.js
