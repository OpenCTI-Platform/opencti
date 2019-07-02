#!/bin/sh

# Start log
/etc/init.d/rsyslog start

# Install Python modules
cd /opt/opencti/worker
pip3 install -r requirements.txt

# Check configuration
while [ ! -f /opt/opencti/shared_config/token ]
do
  echo "Waiting for token in shared config..."
  sleep 2
done

while ! nc -z opencti ${OPENCTI_PORT}; do
  echo "Waiting OpenCTI GraphQL to launch..."
  sleep 2
done

# Replace the token in the configuration
cd /opt/opencti/worker
cp config.yml.docker.sample config.yml.sample
sed -i -e "s/REPLACE_API_KEY/$(cat /opt/opencti/shared_config/token)/g" config.yml.sample
sed -i -e "s/OPENCTI_HOSTNAME/${OPENCTI_HOSTNAME}/g" config.yml.sample
sed -i -e "s/OPENCTI_PORT/${OPENCTI_PORT}/g" config.yml.sample
sed -i -e "s/RABBITMQ_HOSTNAME/${RABBITMQ_HOSTNAME}/g" config.yml.sample
cp config.yml.sample /opt/opencti/shared_config/config_worker.yml

# Start
cd /opt/opencti/worker
python3 worker_import.py &
python3 worker_export.py