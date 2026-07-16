import esbuild from 'esbuild';
import { copy } from 'esbuild-plugin-copy';
import importGlobPluginPkg from 'esbuild-plugin-import-glob';
import graphqlLoaderPluginPkg from '@luckycatfactory/esbuild-graphql-loader';
import nativeNodePlugin from './plugin/native.node.plugin.js';
import nodeGypBuildShimPlugin from './plugin/node-gyp-build-shim.plugin.js';
import { generateEsmPlugin } from './plugin/generate-esm-plugin.js';

const { default: importGlobPlugin } = importGlobPluginPkg;
const { default: graphqlLoaderPlugin } = graphqlLoaderPluginPkg;

const args = process.argv.slice(2);
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

await esbuild.build({
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
  target: ['node20'],
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
});
