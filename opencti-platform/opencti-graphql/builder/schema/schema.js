const esbuild = require('esbuild');
const {default: graphqlLoaderPlugin} = require('@luckycatfactory/esbuild-graphql-loader');

esbuild.build({
    logLevel: 'info',
    plugins: [graphqlLoaderPlugin()],
    entryPoints: ['script/script-generate-schema.js'],
    entryNames: "[name]",
    bundle: true,
    loader: {'.js': 'jsx'},
    platform: 'node',
    target: ['node14'],
    minify: true,
    keepNames: false,
    sourcemap: false,
    sourceRoot: 'src',
    sourcesContent: false,
    outdir: 'build',
    incremental: false,
});
