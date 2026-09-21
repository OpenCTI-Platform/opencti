# =============================================================================
#  OpenCTI — dev container image (v2, mise)
# =============================================================================
# The base is deliberately NEUTRAL: neither Node nor Python is installed here.
# Both runtimes come from mise, driven by the mise.toml at the repository root,
# which is the single source of truth shared with the host and CI.
#
# Do not swap this base for a `node:` or `python:` image: that would reintroduce
# a runtime outside of mise's control, and with it exactly the version drift
# this setup removes.
#
#   docker compose -f .devcontainer/v2/docker-compose.yml build workspace
# =============================================================================
FROM mcr.microsoft.com/devcontainers/base:debian

# --- build toolchain, no runtime ---------------------------------------------
# opencti-graphql/package.json explicitly re-enables the build scripts of two
# native modules despite `enableScripts: false`:
#   "dependenciesMeta": { "node-calls-python": {"built": true}, "re2": {"built": true} }
#
# python3-dev is deliberately NOT installed: the Python headers used at build
# time must be the ones shipped by mise, not those of a system python3 that
# would reintroduce a second version.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      pkg-config \
      libffi-dev \
      ca-certificates \
      curl \
      gpg \
 && rm -rf /var/lib/apt/lists/*

# --- mise, from its official apt repository ----------------------------------
# `arch=amd64,arm64` is essential: the previous .devcontainer downloaded a
# hardcoded x86_64 binary, which made the image unusable on Apple Silicon.
RUN install -dm 755 /etc/apt/keyrings \
 && curl -fsSL https://mise.jdx.dev/gpg-key.pub \
      | gpg --dearmor -o /etc/apt/keyrings/mise-archive-keyring.gpg \
 && echo "deb [signed-by=/etc/apt/keyrings/mise-archive-keyring.gpg arch=amd64,arm64] https://mise.jdx.dev/deb stable main" \
      > /etc/apt/sources.list.d/mise.list \
 && apt-get update && apt-get install -y --no-install-recommends mise \
 && rm -rf /var/lib/apt/lists/*

# THE key line for editor independence. The mise shims must be on PATH for every
# process, not only for interactive shells: language servers, linters and
# debuggers are spawned directly and never source a .bashrc.
#
# This belongs here rather than in devcontainer.json's `containerEnv`, because
# the `${containerEnv:PATH}` substitution needed to prepend to the existing PATH
# is resolved by the VS Code extension but passed through literally by the
# `devcontainer` CLI, which leaves the container with a broken PATH. Setting it
# at build time resolves against the real image PATH and works for every client,
# including a plain `docker exec`.
#
# The shims also export the [env] block of mise.toml (VENV_PATH,
# APP__PYTHON_EXECUTION_VENV) and put .venv/bin first, so a `python` child
# spawned by the backend resolves to the virtual environment.
ENV PATH="/home/vscode/.local/share/mise/shims:${PATH}"

# mise refuses to evaluate a config file it does not trust, and the trust state
# lives in ~/.local/state/mise, which is rebuilt from the image every time the
# container is recreated. Declaring the path as trusted here means the shims
# work immediately, without relying on a lifecycle hook -- so `docker exec` and
# editors that do not run postCreateCommand behave like the others.
ENV MISE_TRUSTED_CONFIG_PATHS=/workspaces/opencti

# mise resolves versions from the config file of the CURRENT directory. Making
# the workspace the default working directory means a bare `docker exec` lands
# where mise.toml applies, instead of / where no version would be set.
WORKDIR /workspaces/opencti

# XDG tree for the vscode user.
#   - share/mise : mount point for the named volume holding the runtimes
#   - state/mise : where mise writes trusted-configs and tracked-configs
#   - .yarn      : Yarn 4 global cache (enableGlobalCache is on by default)
#
# The recursive chown is required: `install -d` only applies -o/-g to the LAST
# path component, leaving .local and .local/share owned by root, which makes
# `mise trust` fail with Permission denied.
#
# These directories are also named-volume mount points. Docker seeds an empty
# named volume from the image content at the mount point, OWNERSHIP INCLUDED, so
# creating them here with the right owner saves a chown in post-create.sh. This
# only works outside the repository bind mount.
RUN mkdir -p /home/vscode/.local/share/mise /home/vscode/.local/state/mise \
             /home/vscode/.yarn \
 && chown -R vscode:vscode /home/vscode/.local /home/vscode/.yarn

# Mount points of the named volumes that live INSIDE the repository bind mount
# (see docker-compose.yml). Docker seeds an empty named volume from the image
# content at the mount point, ownership included, and that also works under a
# bind mount -- so pre-creating them here with the right owner means the first
# `yarn install` does not hit EACCES, with no chown at container start.
#
# The path must match `workspaceFolder` in devcontainer.json.
RUN mkdir -p \
      /workspaces/opencti/node_modules \
      /workspaces/opencti/.venv \
      /workspaces/opencti/opencti-platform/opencti-graphql/node_modules \
      /workspaces/opencti/opencti-platform/opencti-graphql/build \
      /workspaces/opencti/opencti-platform/opencti-front/node_modules \
      /workspaces/opencti/opencti-platform/opencti-front/packages/eslint-plugin-custom-rules/node_modules \
 && chown -R vscode:vscode /workspaces

# `vscode` is just the uid 1000 user shipped by the Microsoft base image; the
# name is historical and has nothing to do with the editor. Every Dev Containers
# implementation that honours `remoteUser` -- VS Code and JetBrains alike --
# runs as this user.
USER vscode

# Convenience for interactive shells only. The shims directory is also injected
# through containerEnv in devcontainer.json, and THAT is the one that matters
# for the language server, the linter and the debugger, none of which ever go
# through an interactive shell.
RUN echo 'eval "$(mise activate bash)"' >> "$HOME/.bashrc" \
 && echo 'eval "$(mise activate zsh)"'  >> "$HOME/.zshrc"
