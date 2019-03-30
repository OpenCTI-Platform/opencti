// eslint-disable-next-line
const fs = require("fs-extra");
const path = require('path');

// Move build directory to api public directory
const FRONT_DIR = path.join(process.env.INIT_CWD, '/build/');
const TARGET_DIR = path.join(
  process.env.INIT_CWD,
  '../opencti-graphql/public/',
);
fs.moveSync(FRONT_DIR, TARGET_DIR, { overwrite: true });
