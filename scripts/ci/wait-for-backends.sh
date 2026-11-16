#!/bin/bash
# Wait for the backend services of docker-compose.yml: the tests check them once at start up, without retry
set -eux
cd "$(dirname "$0")"
# OpenSearch installs a plugin before booting
./wait-for-url-200.sh "http://localhost:9200/_cluster/health?wait_for_status=yellow" 300 2
./wait-for-url-200.sh http://localhost:9000/minio/health/live 120 2
timeout 120 sh -c 'until docker exec rabbitmq rabbitmq-diagnostics -q check_port_connectivity; do sleep 2; done'
timeout 60 sh -c 'until docker exec redis redis-cli ping; do sleep 1; done'
