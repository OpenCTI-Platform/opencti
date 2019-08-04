#!/bin/bash

# Start log
/etc/init.d/rsyslog start

# Sleep a little
sleep 100

# Go to the right directory
cd /opt/opencti-worker

# Launch the worker
python3 worker.py
