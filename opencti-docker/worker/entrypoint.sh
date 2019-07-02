#!/bin/sh

# Start log
/etc/init.d/rsyslog start

# Install Python modules
cd /opt/opencti/worker
sudo -E -H -u ${RUN_USER} pip3 install -r requirements.txt

# Check configuration
while [ ! -f /opt/opencti/shared_config/token ]
do
  echo "Waiting for token in shared config..."
  sleep 2
done

# Replace the token in the configuration
cd /opt/opencti/worker
cp config.yml.docker.sample config.yml.sample
sed -i -e "s/REPLACE_API_KEY/$(cat /opt/opencti/shared_config/token)/g" config.yml.sample
sed -i -e "s/OPENCTI_PORT/${OPENCTI_PORT}/g" config.yml.sample
cp config.yml.sample /opt/opencti/shared_config/config_worker.yml

# Chown the application
if [ $RUN_USER != "root" ]; then
  chown -R ${RUN_USER} /opt/opencti
fi

# Start
cd /opt/opencti/worker
sudo -E -H -u ${RUN_USER} python3 worker_import.py &
sudo -E -H -u ${RUN_USER} python3 worker_export.py