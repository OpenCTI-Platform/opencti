#!/bin/bash
# Usage: ./wait-for-200.sh <URL> <TIMEOUT_SECONDS> <CHECK_INTERVAL_SECONDS>

URL="$1"
TIMEOUT="$2"
INTERVAL="$3"

if [ -z "$URL" ] || [ -z "$TIMEOUT" ] || [ -z "$INTERVAL" ]; then
  echo "Usage: $0 <URL> <TIMEOUT_SECONDS> <CHECK_INTERVAL_SECONDS>"
  exit 1
fi

START=$(date +%s)

while :; do
  elapsed=$(( $(date +%s) - START ))

  if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo "Timeout after ${TIMEOUT}s"
    exit 1
  fi

  # Capture wget output quietly
  output=$(wget --tries=1  --retry-connrefused=0 --server-response --spider -O /dev/null "$URL" 2>&1 >/dev/null)
  # Extract HTTP code if present
  code=$(printf "%s" "$output" | awk '/^  HTTP/{print $2; exit}')

  if [ -n "$code" ]; then
    echo "[$elapsed s] HTTP $code"
    if [ "$code" -eq 200 ]; then
      echo "Success after ${elapsed}s"
      exit 0
    fi
  else
    echo "[$elapsed s] ERROR (no HTTP response)"
  fi

  sleep "$INTERVAL"
done
