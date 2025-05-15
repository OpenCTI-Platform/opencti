const esbuild = require('esbuild');

esbuild.build({
    logLevel: 'info',
    entryPoints: ['script/script-stack-analysis.js'],
    entryNames: "[name]",
    bundle: true,
    loader: { '.js': 'jsx' },
    platform: 'node',
    target: ['node14'],
    sourcemap: false,
    outdir: 'build',
});
