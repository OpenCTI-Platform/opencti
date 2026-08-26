#!/usr/bin/env bash
# One command for the three gates this migration must not commit without.
# It exists because lint was committed red TWICE: the gates were run, then a
# later fix-up edit reopened them and the commit went ahead on stale output.
# Run it as the LAST thing before `git commit`, never earlier.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
fail=0

echo "== eslint (errors only) =="
out=$(cd opencti-platform/opencti-front && yarn eslint src --ext .ts,.tsx,.jsx 2>&1)
n=$(printf '%s\n' "$out" | grep -cE '^[[:space:]]+[0-9]+:[0-9]+[[:space:]]+error')
if [ "$n" -ne 0 ]; then printf '%s\n' "$out" | grep -E '^/|^[[:space:]]+[0-9]+:[0-9]+[[:space:]]+error' | head -20; fail=1; fi
echo "eslint errors: $n"

echo "== tsc =="
(cd opencti-platform/opencti-front && npx tsc --noEmit -p tsconfig.json) || fail=1

echo "== select-conversion guard =="
node fds-migration/scripts/check-select-conversion.mjs || fail=1

# Added after CI caught "Missing frontend key: Refresh interval". Naming a field
# for accessibility means introducing a t_i18n key, and a key with no catalogue
# entry is a red gate the other three do not see.
echo "== i18n keys =="
out=$(cd opencti-platform/opencti-front && node script/verify-translation.js 2>&1)
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q "^Missing" && fail=1

if [ "$fail" -ne 0 ]; then echo "GATES RED — do not commit"; exit 1; fi
echo "GATES GREEN"
