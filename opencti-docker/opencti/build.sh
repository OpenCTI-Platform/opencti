#!/bin/bash

BASEDIR=$(dirname $(realpath "$0"))

echo ${BASEDIR}

# Build the frontend
cd ${BASEDIR}/../../opencti-front
yarn install
yarn build

# Build the GraphQL API
cd ${BASEDIR}/../../opencti-graphql
yarn install
yarn build

# Copy the API in the Docker folder 
cd ${BASEDIR}
rm -Rf opencti-graphql
cp -a ${BASEDIR}/../../opencti-graphql ${BASEDIR}/

# Remove possible development files
rm -Rf opencti-graphql/logs/*
rm -Rf opencti-graphql/.idea
rm -Rf opencti-graphql/.env
rm -Rf opencti-graphql/yarn-error.log

# Clear the configurations and keep only the default one
mv opencti-graphql/config/default.json opencti-graphql/config/default.conf
rm -Rf opencti-graphql/config/*.json
mv opencti-graphql/config/default.conf opencti-graphql/config/default.json

echo "Docker image is ready for building"
