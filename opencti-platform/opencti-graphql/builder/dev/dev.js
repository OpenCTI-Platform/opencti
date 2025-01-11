const esbuild = require('esbuild');
const {default: importGlobPlugin} = require('esbuild-plugin-import-glob');
const {default: graphqlLoaderPlugin} = require('@luckycatfactory/esbuild-graphql-loader');
const nativeNodePlugin = require("../plugin/native.node.plugin");
const {copy} = require('esbuild-plugin-copy');

esbuild.build({
    logLevel: 'info',
    define: {'process.env.NODE_ENV': '\"development\"'},
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
        'script/script-clean-relations.js',
        'script/script-insert-dataset.js',
        'script/script-wait-for-api.js',
    ],
    entryNames: "[name]",
    bundle: true,
    loader: { '.js': 'jsx' },
    platform: 'node',
    target: ['node14'],
    minify: false,
    keepNames: false,
    sourcemap: 'inline',
    outdir: 'build',
});
