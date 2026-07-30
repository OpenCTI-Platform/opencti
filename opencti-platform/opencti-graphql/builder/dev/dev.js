const esbuild = require('esbuild');
const {default: importGlobPlugin} = require('esbuild-plugin-import-glob');
const {default: graphqlLoaderPlugin} = require('@luckycatfactory/esbuild-graphql-loader');
const nativeNodePlugin = require('../plugin/native.node.plugin');
const nodeGypBuildShimPlugin = require('../plugin/node-gyp-build-shim.plugin');
const {copy} = require('esbuild-plugin-copy');

// On Windows with OneDrive, the native .node binary may be a reparse point that
// esbuild's Rust-based resolver cannot follow. Mark the package and its internal
// native-binary path as external so Node.js handles them at runtime instead.
const nodeCallsPythonExternalPlugin = () => ({
  name: 'node-calls-python-external',
  setup(build) {
    // Intercept the top-level package import
    build.onResolve({ filter: /^node-calls-python$/ }, (args) => {
      return { path: args.path, external: true };
    });
    // Intercept the internal native-binary path used inside node-calls-python/index.js
    build.onResolve({ filter: /nodecallspython|build\/Release\/nodecallspython/ }, (args) => {
      return { path: args.path, external: true };
    });
  },
});

esbuild.build({
    logLevel: 'info',
    define: {'process.env.NODE_ENV': '\"development\"'},
    plugins: [
        importGlobPlugin(),
        graphqlLoaderPlugin(),
        nodeCallsPythonExternalPlugin(),
        nativeNodePlugin(),
        nodeGypBuildShimPlugin(),
        copy({
            assets: {
                from: ['./node_modules/@datadog/pprof/prebuilds/**/*'],
                to: ['./prebuilds'],
            }
        }),
        copy({
            assets: {
                from: ['./node_modules/source-map/lib/mappings.wasm'],
                to: ['.'],
            }
        }),
    ],
    entryPoints: [
        'src/back.js',
        'src/lock/child-lock.manager.ts',
        'script/script-clean-relations.js',
        'script/script-insert-dataset.js',
        'script/script-wait-for-api.js',
        'src/utils/safeEjs.worker.ts'
    ],
    entryNames: '[name]',
    bundle: true,
    loader: { '.js': 'jsx' },
    platform: 'node',
    target: ['node14'],
    minifyWhitespace: true,
    minifyIdentifiers: false,
    minifySyntax: true,
    keepNames: false,
    sourcemap: true,
    outdir: 'build',
    external: [
      'apollo-server-errors', // required by graphql-constraint-directive in dead code when using Apollo 4+
      'node-calls-python', // native addon - load via require() at runtime to avoid esbuild bundling issues on Windows/OneDrive
    ],
});
