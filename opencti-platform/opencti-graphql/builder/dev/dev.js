const esbuild = require('esbuild');
const {default: importGlobPlugin} = require('esbuild-plugin-import-glob');
const {default: graphqlLoaderPlugin} = require('@luckycatfactory/esbuild-graphql-loader');
const outputRunPlugin = require("../plugin/output.run.plugin");

esbuild.build({
    logLevel: 'info',
    define: {'process.env.NODE_ENV': '\"development\"'},
    plugins: [importGlobPlugin(), graphqlLoaderPlugin(), outputRunPlugin()],
    entryPoints: [
        'src/index.js',
        'script/script-clean-relations.js'
    ],
    entryNames: "[name]",
    bundle: true,
    loader: {'.js': 'jsx'},
    platform: 'node',
    target: ['node14'],
    minify: false,
    keepNames: true,
    sourcemap: true,
    sourceRoot: 'src',
    sourcesContent: true,
    outdir: 'build',
    incremental: true,
    watch: true,
}).catch((error) => {
    console.error(error);
    process.exit(1);
});
