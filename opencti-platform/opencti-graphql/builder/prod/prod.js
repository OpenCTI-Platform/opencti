const esbuild = require('esbuild');
const {default: importGlobPlugin} = require('esbuild-plugin-import-glob');
const {default: graphqlLoaderPlugin} = require('@luckycatfactory/esbuild-graphql-loader');
const nativeNodePlugin = require("../plugin/native.node.plugin");
const {copy} = require("esbuild-plugin-copy");

esbuild.build({
    logLevel: 'info',
    define: {'process.env.NODE_ENV': '\"production\"'},
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
        'script/script-clean-relations.js'
    ],
    entryNames: "[name]",
    bundle: true,
    loader: {'.js': 'jsx'},
    platform: 'node',
    target: ['node14'],
    minifyWhitespace: true,
    minifyIdentifiers: false,
    minifySyntax: true,
    keepNames: false,
    sourcemap: true,
    sourceRoot: 'src',
    sourcesContent: false,
    outdir: 'build',
});
