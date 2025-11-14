#!/bin/bash

FILE_MONITOR="docker_stats.log"
FILE_PID="monitor.pid"

while true; do
  echo "==== $(date) ====" >> $FILE_MONITOR
  echo "-- Docker stats" >> $FILE_MONITOR
  docker stats --no-stream >>  $FILE_MONITOR
  echo "-- Memory" >> $FILE_MONITOR
  free -m >>  $FILE_MONITOR
  echo "-- CPU" >> $FILE_MONITOR
  echo "Total CPU: $(top -bn1 | awk -F',' '/Cpu/ {sub(/^[^0-9]+/, "", $4); print 100 - $4 "%"}')"  >>  $FILE_MONITOR
  echo "Main cpu consumer" >> $FILE_MONITOR
  ps -eo pid,comm,%cpu --sort=-%cpu | head -n 5 >>  $FILE_MONITOR
  sleep 60
done
