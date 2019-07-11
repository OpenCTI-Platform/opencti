#!/bin/sh

# Start log
/etc/init.d/rsyslog start

# Go to the right directory
cd /opt/opencti-worker

# Launch 4 import workers
python3 worker_import.py &
python3 worker_import.py &
python3 worker_import.py &
python3 worker_import.py &

# Launch 4 export workers
python3 worker_export.py &
python3 worker_export.py &
python3 worker_export.py &
python3 worker_export.py &

# Loop
sleep infinity
