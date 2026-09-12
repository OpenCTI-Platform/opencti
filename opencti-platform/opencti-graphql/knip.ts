import { defineConfig } from 'knip/config';
import { BUILD_ENTRY_POINTS } from './builder/entry-points.js';

export default defineConfig({
  entry: [
    ...BUILD_ENTRY_POINTS,
    'tests/**/*-test.{ts,js}',
    'vitest.config*.ts',
  ],
  project: [
    'src/**/*.{ts,js}',
    'tests/**/*.{ts,js}',
    'script/**/*.{ts,js}',
    'builder/**/*.{js,cjs,mjs}',
  ],
  ignore: [
    'src/generated/**',
    'src/__generated__/**',
  ],
  // Provided by the runtime image, not by npm.
  ignoreBinaries: ['pip3', 'java', 'run'],
  ignoreUnresolved: [
    // Expanded at build time by esbuild-plugin-import-glob. Regex because knip reads the
    // literal `{js,ts}` form as a glob of its own and never matches it.
    '../migrations/.*',
    './general',
    './stix',
  ],
});
