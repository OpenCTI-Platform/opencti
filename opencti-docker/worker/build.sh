#!/bin/bash

BASEDIR=$(dirname $(realpath "$0"))

# Build the frontend
cd ${BASEDIR}
rm -Rf opencti-worker
cp -a ${BASEDIR}/../../opencti-worker ${BASEDIR}/

# Remove possible development files
rm -Rf opencti-worker/__pycache__
rm -Rf opencti-worker/.idea

# Clear the configurations and keep only the default one
rm -Rf opencti-worker/config.yml

echo "Docker image is ready for building"
