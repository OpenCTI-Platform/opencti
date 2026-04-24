const esbuild = require('esbuild');
const fs = require('fs');
const path = require('path');

esbuild.build({
  logLevel: 'info',
  entryPoints: ['src/public/workers/graphql.worker.ts'],
  bundle: true,
  format: 'iife',
  minify: false,
  target: ['chrome58'],
  outdir: 'tmp/workers-final',
  entryNames: '[name]',
  loader: { '.js': 'jsx' },
  external: ['prettier', 'prettier/standalone', 'prettier/parser-graphql'],
}).then(() => {
  const content = fs.readFileSync('tmp/workers-final/graphql.worker.js', 'utf8');
  const onmessagePos = content.indexOf('globalThis.onmessage');
  const initCallPos = content.lastIndexOf('initialize(');
  console.log('BUILD OK');
  console.log('Has GraphQLWorker:', content.includes('GraphQLWorker'));
  console.log('Has onmessage:', content.includes('onmessage'));
  console.log('Last initialize() is AFTER onmessage setter:', initCallPos > onmessagePos);
  console.log('File size:', Math.round(content.length / 1024) + 'KB');
}).catch(e => { console.error('BUILD FAILED:', e.message); process.exit(1); });

