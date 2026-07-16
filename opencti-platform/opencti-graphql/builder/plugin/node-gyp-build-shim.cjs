/**
 * Shim for node-gyp-build used in the esbuild bundle, ignore directory parameter, use __dirname instead
 */

const nodeGypBuild = require('node-gyp-build/node-gyp-build.js');

module.exports = () => {
  return nodeGypBuild(__dirname);
};
