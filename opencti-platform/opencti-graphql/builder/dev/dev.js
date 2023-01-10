const esbuild = require('esbuild');
const {default: importGlobPlugin} = require('esbuild-plugin-import-glob');
const {default: graphqlLoaderPlugin} = require('@luckycatfactory/esbuild-graphql-loader');
const nativeNodePlugin = require("../plugin/native.node.plugin");

esbuild.build({
    logLevel: 'info',
    define: {'process.env.NODE_ENV': '\"development\"'},
    plugins: [importGlobPlugin(), graphqlLoaderPlugin(), nativeNodePlugin()],
    entryPoints: [
        'src/back.js',
        'script/script-clean-relations.js',
        'script/script-insert-dataset.js'
    ],
    entryNames: "[name]",
    bundle: true,
    loader: { '.js': 'jsx' },
    platform: 'node',
    target: ['node14'],
    minify: false,
    keepNames: true,
    sourcemap: 'inline',
    outdir: 'build',
    incremental: false,
    watch: false,
});
