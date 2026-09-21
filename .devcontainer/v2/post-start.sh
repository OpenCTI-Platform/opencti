#!/usr/bin/env bash
# =============================================================================
#  OpenCTI — platform start (v2, mise)
# =============================================================================
# Brings the API and the frontend up, so that opening the workspace is enough to
# have the application answering in the browser -- the first day and every day
# after.
#
# Two callers, and no editor among them. The workspace container runs this as its
# `command:` on every start, and post-create.sh calls it once provisioning is
# done, for the very first one. `postStartCommand` would be the specified hook,
# but JetBrains does not run it.
#
# It must return immediately: the container's command goes on to `sleep infinity`
# and post-create.sh is awaited by the editor, so a server started in the
# foreground here would hang one or the other. Both processes are therefore
# detached, and their output goes to a log file rather than to a terminal.
#
#   tail -f /tmp/opencti-back.log
#   tail -f /tmp/opencti-front.log
#
# To take the wheel back -- run the servers by hand in an IDE terminal, where you
# get the logs and the debugger -- set OPENCTI_AUTOSTART=0 in the `environment`
# block of docker-compose.yml, or just stop them once started.
# =============================================================================
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ "${OPENCTI_AUTOSTART:-1}" = "0" ]; then
  echo "OPENCTI_AUTOSTART=0 -- not starting anything"
  exit 0
fi

# A container can be started before it has ever been provisioned, if
# post-create.sh failed or was interrupted. Starting the servers then would only
# produce a confusing stack trace in a log file nobody is watching.
if [ ! -d node_modules ] || [ ! -d opencti-platform/opencti-graphql/node_modules ]; then
  echo "workspace not provisioned yet -- run 'bash .devcontainer/v2/post-create.sh' first"
  exit 0
fi

# Started twice, the second one would sit on Nx's lock for the same continuous
# target and never come up. The listening port is the honest test: it says the
# server is actually there, where a process name only says something was
# launched.
start_if_down() {
  local name="$1" port="$2"
  shift 2
  if ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN; then
    echo "  $name already listening on $port"
    return 0
  fi
  # setsid detaches from this hook's session, so the servers survive the client
  # that triggered the start closing its connection.
  setsid nohup "$@" > "/tmp/opencti-$name.log" 2>&1 &
  echo "  $name starting -- tail -f /tmp/opencti-$name.log"
}

start_if_down back 4000 mise run dev:back

# `--host 0.0.0.0` is passed HERE and nowhere else, because it is true here and
# nowhere else. Vite binds [::1] alone by default, the editor's port forwarder
# comes in over IPv4, and the two never meet -- measured: 127.0.0.1:3000 refuses
# the connection while [::1]:3000 answers 200.
#
# It does not belong in mise.toml, which the host shares, nor in vite.config.ts,
# which is the application's: on a laptop the same flag would publish an
# unauthenticated dev server to the local network. Nothing is published out of
# this container, so binding every interface inside it exposes nothing.
#
# The command is spelled out rather than reusing `mise run dev:front`, because Nx
# swallows the flag on its way through -- `mise run dev:front -- --version` prints
# Nx's version, not Vite's. `yarn dev` is still what runs, so `yarn relay` keeps
# happening first.
start_if_down front 3000 bash -c 'cd "$(git -C /workspaces/opencti rev-parse --show-toplevel)/opencti-platform/opencti-front" && exec mise exec -- yarn dev --host 0.0.0.0'

echo "  the API takes a minute or so to build and boot before the UI answers"
