#!/bin/env bash

# Backup and remove any existing global OpenSpec configurations.
OPENSPEC_CONFIG_PATH="$(openspec config path)"
OPENSPEC_CONFIG_PATH_BACKUP="${OPENSPEC_CONFIG_PATH}.$(date +%s).bkp"
if [[ -f "${OPENSPEC_CONFIG_PATH}" ]]; then
  printf "Found existing OpenSpec config: %s\n" "${OPENSPEC_CONFIG_PATH}"
  printf "Will back up existing config (%s), then delete.\n" "${OPENSPEC_CONFIG_PATH_BACKUP}"
  cp "${OPENSPEC_CONFIG_PATH}" "${OPENSPEC_CONFIG_PATH_BACKUP}"
  rm "${OPENSPEC_CONFIG_PATH}"
fi

# Uncomment to disable telemtry
OPENSPEC_TELEMETRY=0

# Create global OpenSpec config with core profile.
openspec config profile core

# Set correct profile and delivery (commands and skills)
openspec config set profile custom
openspec config set delivery both

# Enable all required workflows.
# Requires jq to be installed, otherwise enable all workflows by running this interactive mode: `openspec config profile`
if command -v jq >/dev/null 2>&1; then
  OPENSPEC_CONFIG_PATH="$(openspec config path)"
  OPENSPEC_TMP_FILE="$(mktemp)"
  jq '.workflows = ["propose", "explore", "new", "continue", "apply", "ff", "sync", "archive", "bulk-archive", "verify"]' "$OPENSPEC_CONFIG_PATH" > "$OPENSPEC_TMP_FILE" && mv "$OPENSPEC_TMP_FILE" "$OPENSPEC_CONFIG_PATH"
  printf "\nSuccess\!\n\nOpenSpec is correctly configured for SuperSpec and has the following workflows enabled: \n%s\n\n" "$(openspec config get workflows)"
else
  printf "\nWarning: jq was not found on your system.\n\nRun the following command manually:\nopenspec config profile\n\n"
  printf "During interactive process:\n  Select: Change \"Workflows Only\"\n  Enable all workflows\n\n"
  printf "Once completed, run this command to confirm all workflows are available:\nopenspec config get workflows\n"
fi
