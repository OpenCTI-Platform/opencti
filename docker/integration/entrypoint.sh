#!/bin/sh

# Start log
/etc/init.d/rsyslog start

# Install Python modules
cd /opt/opencti/integration
sudo -E -H -u ${RUN_USER} pip3 install -r requirements.txt

# Install Python modules of each connectors
sudo -E -H -u ${RUN_USER} find connectors -name requirements.txt -exec pip3 install -r {} \;

# Check configuration
while [ ! -f /opt/opencti/shared_config/config.yml ]
do
  echo "Waiting for shared config..."
  sleep 2
done

# Chown the application
chown -R ${RUN_USER} /opt/opencti

# Start
cd /opt/opencti/integration
sudo -E -H -u ${RUN_USER} python3 connectors_scheduler.py
