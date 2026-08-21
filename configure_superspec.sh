#!/bin/env bash

git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/danielhanold/superspec.git /tmp/superspec-tmp && \
  cd /tmp/superspec-tmp && \
  git sparse-checkout set openspec/schemas/superspec && \
  cd - && \
  mkdir -p openspec/schemas/superspec && \
  cp -r /tmp/superspec-tmp/openspec/schemas/superspec/. openspec/schemas/superspec/ && \
  rm -rf /tmp/superspec-tmp