#!/bin/sh

mkdir ./licenses
pwd
ls
cd ./opencti-platform/opencti-front && npx --yes license-checker-rseidelsohn --production --includePackages "$all_deps_check" --summary --out ../../licenses/front_deps.txt
cd ../opencti-graphql && npx --yes license-checker-rseidelsohn --production --includePackages "$all_deps_check" --summary --out ../../licenses/back_deps.txt
cd ../.. && npx --yes generate-license-file --config generatelicenseconfig.json --no-spinner --ci
