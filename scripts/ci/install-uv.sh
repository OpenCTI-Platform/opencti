#!/bin/sh
# Installs the uv binary of a pinned release into the given directory, for Linux x86_64 CI
# environments that cannot copy it from the ghcr.io/astral-sh/uv image (CircleCI, Read the Docs).
# The archive is verified against its SHA-256; Renovate updates the version and the checksum together.
set -eu

UV_VERSION=0.12.9
UV_SHA256=ec7a99cd05e0cd7f80243f135ce1361c76835cb0ee60055d14d20eba8eba1460

dest="$1"
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT

curl -fsSLo "$archive" "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz"
echo "${UV_SHA256}  ${archive}" | sha256sum -c -
mkdir -p "$dest"
tar -xzf "$archive" -C "$dest" --strip-components=1 uv-x86_64-unknown-linux-gnu/uv
