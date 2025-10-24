#!/bin/sh
set -euo pipefail

usage() {
  echo "Usage: $0 <BASE_NAME>"
  echo
  echo "Mandatory arguments:"
  echo "  BASE_NAME   OpenCTI instance base name"
  exit 1
}

if [[ $# -ne 1 ]]; then
  usage
fi

BASE_NAME="$1"

echo "$(date): Starting instance: ${BASE_NAME}-opencti"

export APP__PORT=4100
export APP__ADMIN__PASSWORD=admin
export APP__CHILD_LOCKING_PROCESS__ENABLED=false
export APP__ADMIN__TOKEN=bfa014e0-e02e-4aa6-a42b-603b19dcf159
export APP__HEALTH_ACCESS_KEY=cihealthkey
export APP__APP_LOG__EXTENDED_ERROR_MESSAGE=true
export EXPIRATION_SCHEDULER__ENABLED=false
export SUBSCRIPTION_SCHEDULER__ENABLED=false
export APP__ENABLED_DEV_FEATURES='["*"]'

# Backend endpoint
export REDIS__HOSTNAME=redis
export REDIS__NAMESPACE=${BASE_NAME}-start
export ELASTICSEARCH__URL=http://elasticsearch:9200
export ELASTICSEARCH__INDEX_PREFIX=${BASE_NAME}-start
export MINIO__ENDPOINT=minio
export MINIO__BUCKET_NAME=${BASE_NAME}-start-bucket
export RABBITMQ__HOSTNAME=rabbitmq
export RABBITMQ__QUEUE_PREFIX=${BASE_NAME}-start

cd /home/workspace
ls -lart
apk add build-base git libffi-dev cargo
mkdir -p /tmp/platform/
echo -e "\n ********* Copy reference platform locally"; sleep 1
cp -a /home/workspace/platform-reference/* /tmp/platform/
ls -lart /tmp/platform/
echo -e "\n **************** \n ** Install client python \n ****************"; sleep 1
cd client-python
pip install -r requirements.txt
pip install -e .[dev,doc]
cd /tmp/platform/opencti-graphql
echo -e "\n **************** \n ** Yan install \n ****************"; sleep 1
yarn install
yarn install:python
echo -e "\n **************** \n **  STARTING ${BASE_NAME}-opencti INSTANCE \n ****************"; sleep 1
NODE_OPTIONS=--max_old_space_size=6000 yarn start

