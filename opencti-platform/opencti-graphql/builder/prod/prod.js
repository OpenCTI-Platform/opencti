const esbuild = require('esbuild');
const {default: importGlobPlugin} = require('esbuild-plugin-import-glob');
const {default: graphqlLoaderPlugin} = require('@luckycatfactory/esbuild-graphql-loader');

esbuild.build({
    logLevel: 'info',
    define: {'process.env.NODE_ENV': '\"production\"'},
    plugins: [importGlobPlugin(), graphqlLoaderPlugin()],
    entryPoints: [
        'src/index.js',
        'script/script-clean-relations.js'
    ],
    entryNames: "[name]",
    bundle: true,
    loader: {'.js': 'jsx'},
    platform: 'node',
    target: ['node14'],
    minify: true,
    keepNames: true,
    sourcemap: true,
    sourceRoot: 'src',
    sourcesContent: false,
    outdir: 'build',
    incremental: false,
});
