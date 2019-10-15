#!/bin/sh

# Correct working directory
cd /opt/opencti

# Start
node --max_old_space_size=8192 dist/server.js
