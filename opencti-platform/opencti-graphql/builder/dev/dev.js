const esbuild = require('esbuild');
const {default: importGlobPlugin} = require('esbuild-plugin-import-glob');
const {default: graphqlLoaderPlugin} = require('@luckycatfactory/esbuild-graphql-loader');
const nativeNodePlugin = require('../plugin/native.node.plugin');
const {copy} = require('esbuild-plugin-copy');

const config = {
    logLevel: 'info',
    define: {'process.env.NODE_ENV': '"development"'},
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
};

const shouldWatch = process.argv.includes('--watch');

if (shouldWatch) {
    let buildCount = 0;
    
    // Add a plugin to log rebuild events
    const watchPlugin = {
        name: 'watch-plugin',
        setup(build) {
            let startTime;
            build.onStart(() => {
                startTime = Date.now();
                buildCount++;
                if (buildCount > 1) {
                    console.log('🔨 Rebuilding...');
                }
            });
            build.onEnd((result) => {
                const duration = Date.now() - startTime;
                if (result.errors.length > 0) {
                    console.error(`❌ Build failed with ${result.errors.length} error(s)`);
                    // Notify the parent so it can cancel any pending restart
                    if (process.send && buildCount > 1) {
                        process.send({ type: 'rebuild-failed' });
                    }
                } else {
                    if (buildCount === 1) {
                        console.log('✅ Initial build complete');
                        // Signal the parent (watch.js) via IPC that the initial
                        // build is done so it can start the app process.
                        if (process.send) {
                            process.send({ type: 'initial-build-complete' });
                        }
                    } else {
                        console.log(`✅ Rebuild complete in ${duration}ms`);
                        // Signal the parent to restart the app process.
                        if (process.send) {
                            process.send({ type: 'rebuild-complete' });
                        }
                    }
                }
            });
        },
    };

    const watchConfig = {
        ...config,
        plugins: [...config.plugins, watchPlugin],
    };

    (async () => {
        const context = await esbuild.context(watchConfig);
        await context.watch();
        console.log('👀 Watching for changes...');
    })();
} else {
    esbuild.build(config);
}
