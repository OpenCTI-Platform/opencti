#!/bin/sh

# Start log
/etc/init.d/rsyslog start

# Upgrade schema & do migrations
cd /opt/opencti/worker
sudo -H -u ${RUN_USER} pip3 install -r requirements.txt

# Check configuration
echo "Waiting for token in shared config..."
while [ ! /opt/opencti/shared_config/token ]
do
  sleep 1
done

# Replace the token in the configuration
sed -i -e "s/REPLACE_API_KEY/${`cat /opt/opencti/shared_config/token`}/g" /opt/opencti/worker/config.yml.sample
cp /opt/opencti/worker/config.yml.sample /opt/opencti/worker/config.yml

# Chown the application
chown -R ${RUN_USER} /opt/opencti

# Start
sudo -H -u ${RUN_USER} python3 worker_import.py &
sudo -H -u ${RUN_USER} python3 worker_export.py
