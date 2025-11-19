import esbuild from 'esbuild';
import { copy } from 'esbuild-plugin-copy';
import importGlobPluginPkg from 'esbuild-plugin-import-glob';
import graphqlLoaderPluginPkg from '@luckycatfactory/esbuild-graphql-loader';
import nativeNodePlugin from './plugin/native.node.plugin.js';
import nodeGypBuildShimPlugin from './plugin/node-gyp-build-shim.plugin.js';
import { generateEsmPlugin } from './plugin/generate-esm-plugin.js';

const { default: importGlobPlugin } = importGlobPluginPkg;
const { default: graphqlLoaderPlugin } = graphqlLoaderPluginPkg;

const args = process.argv.slice(2).filter((a) => a !== '--watch');
const isWatch = process.argv.includes('--watch');
const arg = args.shift();
const isScript = arg === '--script';
const isDev = isScript || arg === '--development';
const scriptName = isScript ? args.shift() : undefined;

const entryPoints = [];

if (scriptName) {
  entryPoints.push(scriptName);
} else {
  entryPoints.push(...[
    'src/back.ts',
    'src/lock/child-lock.manager.ts',
    'script/script-clean-relations.js',
    'script/script-insert-dataset.js',
    'src/utils/safeEjs.worker.ts'
  ]);
}

const buildOptions = {
  logLevel: 'info',
  define: {'process.env.NODE_ENV': JSON.stringify(isDev ? 'development' : 'production')},
  plugins: [
    generateEsmPlugin(),
    importGlobPlugin(),
    graphqlLoaderPlugin(),
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
  entryPoints,
  entryNames: '[name]',
  bundle: true,
  platform: 'node',
  target: ['node22'],
  minifyWhitespace: !isDev,
  minifyIdentifiers: false,
  minifySyntax: !isDev,
  lineLimit: isDev ? undefined : 160,
  keepNames: true,
  sourcemap: true,
  outdir: 'build',
  external: [
    'apollo-server-errors', // required by graphql-constraint-directive in dead code when using Apollo 4+
  ],
};

if (isWatch) {
  let buildCount = 0;

  // Log rebuild events so the watch runner (builder/dev/watch.js) can detect them
  const watchPlugin = {
    name: 'watch-plugin',
    setup(build) {
      let startTime;
      build.onStart(() => {
        startTime = Date.now();
        buildCount += 1;
        if (buildCount > 1) {
          console.log('🔨 Rebuilding...');
        }
      });
      build.onEnd((result) => {
        const duration = Date.now() - startTime;
        if (result.errors.length > 0) {
          console.error(`❌ Build failed with ${result.errors.length} error(s)`);
        } else if (buildCount === 1) {
          console.log('✅ Initial build complete');
        } else {
          console.log(`✅ Rebuild complete in ${duration}ms`);
        }
      });
    },
  };

  const context = await esbuild.context({
    ...buildOptions,
    plugins: [...buildOptions.plugins, watchPlugin],
  });
  await context.watch();
  console.log('👀 Watching for changes...');
} else {
  await esbuild.build(buildOptions);
}
