#!/bin/sh

mkdir ../licenses
cd ../opencti-platform/opencti-front && npx license-checker-rseidelsohn --production --includePackages "$all_deps_check" --summary --out ../../licenses/front_deps.txt
cd ../opencti-graphql && npx license-checker-rseidelsohn --production --includePackages "$all_deps_check" --summary --out ../../licenses/back_deps.txt
cd ../.. && npx --yes generate-license-file --config generatelicenseconfig.json --no-spinner --ci
