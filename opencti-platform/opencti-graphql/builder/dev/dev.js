const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');
const {default: importGlobPlugin} = require('esbuild-plugin-import-glob');
const {default: graphqlLoaderPlugin} = require('@luckycatfactory/esbuild-graphql-loader');
const nativeNodePlugin = require('../plugin/native.node.plugin');
const {copy} = require('esbuild-plugin-copy');

// safeEjs evaluates the ejs sources inside its sandbox; inline them so the bundle needs no node_modules.
const ejsDirectory = path.dirname(require.resolve('ejs'));
const safeEjsSources = Object.fromEntries(['ejs.js', 'utils.js'].map((file) => [file, fs.readFileSync(path.join(ejsDirectory, file), 'utf8')]));

esbuild.build({
    logLevel: 'info',
    define: {
        'process.env.NODE_ENV': '\"development\"',
        __SAFE_EJS_SOURCES__: JSON.stringify(safeEjsSources),
    },
    plugins: [
        importGlobPlugin(),
        graphqlLoaderPlugin(),
        nativeNodePlugin(),
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
    ],
});
