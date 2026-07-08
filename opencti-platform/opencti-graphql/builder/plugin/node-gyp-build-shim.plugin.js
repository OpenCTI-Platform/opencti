/**
 * Esbuild plugin that redirects require('node-gyp-build') to a shim which
 * calls the real node-gyp-build with the correct bundle directory.
 */

const path = require('path');

const nodeGypBuildShimPlugin = () => ({
  name: 'node-gyp-build-shim',
  setup: (build) => {
    build.onResolve({ filter: /^node-gyp-build$/ }, () => ({
      path: path.resolve(__dirname, 'node-gyp-build-shim.js'),
    }));
  },
});

module.exports = nodeGypBuildShimPlugin;
