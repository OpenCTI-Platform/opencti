#!/bin/zsh
# Local backend for the Procedure entity prototype (feat/procedure-entity) on :4006. Isolated from the other local
# stacks via separate ES index / Redis namespace / MinIO bucket / Rabbit queue prefixes. Safe to delete.
cd "$(dirname "$0")"
export PATH="$HOME/.local/python3.14/bin:$HOME/.local/node22/bin:$PATH"
export APP__PORT=4006
export APP__BASE_URL=http://localhost:4006/
export REDIS__HOSTNAME=localhost REDIS__PORT=6379 REDIS__NAMESPACE=proc
export ELASTICSEARCH__URL=http://localhost:9200 ELASTICSEARCH__INDEX_PREFIX=opencti_proc
export MINIO__ENDPOINT=127.0.0.1 MINIO__PORT=9000 MINIO__USE_SSL=false MINIO__BUCKET_NAME=opencti-proc-bucket
export RABBITMQ__HOSTNAME=127.0.0.1 RABBITMQ__PORT=5672 RABBITMQ__QUEUE_PREFIX=proc_
# Credentials shared with the main local dev stack
eval "$(grep -E '^export (MINIO__ACCESS_KEY|MINIO__SECRET_KEY|APP__ADMIN__|APP__ENCRYPTION_KEY)' "$HOME/src/opencti repo/opencti/opencti-platform/opencti-graphql/start-backend-dev.sh")"
exec yarn start
