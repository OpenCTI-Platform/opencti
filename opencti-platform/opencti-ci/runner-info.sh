#!/bin/bash
set -x

echo -e "Runner Name: $RUNNER_NAME \n Runner OS: $RUNNER_OS \n Runner Arch: $RUNNER_ARCH"
echo -e "Workflow: ${GITHUB_WORKFLOW} \t Run ID: ${GITHUB_RUN_ID} \t Run Number: ${GITHUB_RUN_NUMBER}"
echo -e "Workspace  GITHUB_WORKSPACE =  ${GITHUB_WORKSPACE}  \t  pwd $(pwd) "
env

FILE_MONITOR="runner_resource_stat.log"
FILE_PID="monitor.pid"

while true; do
  echo "==== $(date) ====" >> $FILE_MONITOR
  echo "- Docker stats" >> $FILE_MONITOR
  docker stats --no-stream >>  $FILE_MONITOR
  echo "- Memory" >> $FILE_MONITOR
  free -m >>  $FILE_MONITOR
  echo "- CPU" >> $FILE_MONITOR
  echo "Total CPU: $(top -bn1 | awk -F',' '/Cpu/ {sub(/^[^0-9]+/, "", $4); print 100 - $4 "%"}')"  >>  $FILE_MONITOR
  echo "Main cpu consumers:" >> $FILE_MONITOR
  ps -eo pid,comm,%cpu --sort=-%cpu | head -n 5 >>  $FILE_MONITOR
  sleep 60
done &
