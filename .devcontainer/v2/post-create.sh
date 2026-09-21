#!/usr/bin/env bash
# =============================================================================
#  OpenCTI — dev container post-create hook (v2, mise)
# =============================================================================
# Run once per container CREATION by every Dev Containers implementation that
# honours `postCreateCommand` -- VS Code, JetBrains, and the `devcontainer` CLI
# alike. Nothing here is client-specific.
#
# It is also safe to run by hand, which is the fallback for anyone attaching
# with a bare `docker exec`:
#
#   bash .devcontainer/v2/post-create.sh
#
# Every step is idempotent: re-running it on an already-provisioned container
# does nothing but print. That matters because the named volumes survive a
# container rebuild, so this script meets a half-provisioned workspace far more
# often than an empty one.
# =============================================================================
set -euo pipefail

# The hook's working directory is `workspaceFolder` for most clients, but not
# all, and not for a hand-run. Anchor on the script's own location instead.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

step() { printf '\n==> %s\n' "$*"; }

# `sudo` is only needed for the ownership repair below, and only when this runs
# as a non-root user -- which is the normal case (`remoteUser: vscode`).
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

# -----------------------------------------------------------------------------
# 1. Ownership of the named-volume mount points -- a safety net, not the mechanism
# -----------------------------------------------------------------------------
# Docker creates an empty named volume as root, and seeds it from the image
# content at the mount point, ownership included. The Dockerfile pre-creates all
# of these owned by the container user, so a volume created from that image is
# already correct and this loop is a no-op.
#
# It still earns its place in two cases the seeding cannot cover:
#   - a volume created by an EARLIER build, before the pre-creation was added;
#   - Linux hosts, where `updateRemoteUserUID` renumbers the container user to
#     match the host's uid AFTER the image was built, leaving these directories
#     owned by the uid 1000 baked in at build time.
#
# `chown -R` looks expensive but is not: it only ever runs on a directory we do
# not own, and a directory we do not own is one nothing has been able to write
# to -- so it is empty.
step "Checking ownership of the named-volume mount points"
VOLUME_MOUNTPOINTS=(
  node_modules
  .venv
  opencti-platform/opencti-graphql/node_modules
  opencti-platform/opencti-graphql/build
  opencti-platform/opencti-front/node_modules
  opencti-platform/opencti-front/packages/eslint-plugin-custom-rules/node_modules
  "$HOME/.local/share/mise"
  "$HOME/.yarn"
)
to_fix=()
for dir in "${VOLUME_MOUNTPOINTS[@]}"; do
  [ -d "$dir" ] || continue
  [ "$(stat -c '%u' "$dir")" = "$(id -u)" ] && continue
  to_fix+=("$dir")
done
if [ ${#to_fix[@]} -eq 0 ]; then
  echo "    all ${#VOLUME_MOUNTPOINTS[@]} already owned by $(id -un) -- nothing to do"
else
  printf '    repairing: %s\n' "${to_fix[@]}"
  $SUDO chown -R "$(id -u):$(id -g)" "${to_fix[@]}"
fi

# -----------------------------------------------------------------------------
# 2. Runtimes
# -----------------------------------------------------------------------------
# Installs exactly what mise.toml pins, and creates the .venv declared by its
# `_.python.venv` entry. Re-running it on an up-to-date container prints
# "already installed" and exits.
#
# No `mise trust` here: the Dockerfile sets MISE_TRUSTED_CONFIG_PATHS, so the
# config is trusted for every process in the container -- including the ones
# that never run this hook, like a plain `docker exec`. Trusting again from here
# would write the same state to a second place and hide that dependency.
step "Installing the runtimes pinned by mise.toml"
mise install

# -----------------------------------------------------------------------------
# 3. Yarn, through corepack
# -----------------------------------------------------------------------------
# package.json pins `packageManager: yarn@4.18.0+sha512...`; corepack is what
# turns that field into a real binary, and it ships inside the Node that mise
# just installed. `corepack enable` itself only writes shims; the yarn tarball is
# fetched, and checksum-verified against that field, on the first real yarn call
# -- which is the version check closing this step.
#
# `mise reshim` is the part that is easy to miss: corepack writes `yarn` into
# mise's node install directory, and mise only exposes what is in its shims
# directory -- which is what PATH points at. Without the reshim, `yarn` exists
# on disk and is still "command not found".
step "Enabling yarn through corepack"
# Without this, corepack asks for confirmation before its first download and
# blocks the hook on any client that gives it a TTY.
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
corepack enable
mise reshim
echo "    yarn $(yarn --version) at $(command -v yarn)"

# -----------------------------------------------------------------------------
# 4. Dependencies of the four applications
# -----------------------------------------------------------------------------
# The real work lives in mise.toml's [tasks], not here, so that a developer
# working on the host without a container runs the exact same thing.
step "Bootstrapping the workspace"
mise run setup

# -----------------------------------------------------------------------------
# 5. First start
# -----------------------------------------------------------------------------
# Every later start is handled by the container's own `command:`, which runs
# post-start.sh before going to sleep. This one cannot be: at the moment the
# container started, node_modules did not exist yet and the script rightly
# refused to launch anything. Calling it here is what makes day one behave like
# every other day -- the workspace opens and the application is coming up.
step "Starting the platform"
bash "$(dirname "${BASH_SOURCE[0]}")/post-start.sh"
