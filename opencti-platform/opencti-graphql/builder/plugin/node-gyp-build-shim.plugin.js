/**
 * Esbuild plugin that redirects require('node-gyp-build') to a shim which
 * calls the real node-gyp-build with the correct bundle directory.
 */

import {fileURLToPath} from 'node:url';

const nodeGypBuildShimPlugin = () => ({
  name: 'node-gyp-build-shim',
  setup: (build) => {
    build.onResolve({ filter: /^node-gyp-build$/ }, () => ({
      path: fileURLToPath(new URL('node-gyp-build-shim.cjs', import.meta.url)),
    }));
  },
});

export default nodeGypBuildShimPlugin;
