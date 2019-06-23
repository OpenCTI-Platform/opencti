#!/bin/sh

# Start log
/etc/init.d/rsyslog start

# Install Python modules
cd /opt/opencti/integration
sudo -H -u ${RUN_USER} pip3 install -r requirements.txt

# Install Python modules of each connectors
sudo -H -u ${RUN_USER} find connectors -name requirements.txt -exec pip3 install -r {} \;

# Check configuration
while [ ! -f /opt/opencti/shared_config/token ]
do
  echo "Waiting for token in shared config..."
  sleep 2
done

# Replace the token in the configuration
sed -i -e "s/REPLACE_API_KEY/$(cat /opt/opencti/shared_config/token)/g" /opt/opencti/integration/config.yml.sample
cp /opt/opencti/integration/config.yml.sample /opt/opencti/shared_config/config.yml

# Chown the application
chown -R ${RUN_USER} /opt/opencti

# Start
cd /opt/opencti/integration
sudo -H -u ${RUN_USER} python3 connectors_scheduler.py
