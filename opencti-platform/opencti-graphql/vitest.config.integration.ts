import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';
import type { PluginOption } from 'vite';
import { BaseSequencer, type TestSpecification } from 'vitest/node';

export const buildIntegrationTestConfig = (include: string[]) => defineConfig({
  plugins: [graphql() as PluginOption],
  test: {
    dir: './tests',
    include,
    testTimeout: 1200000,
    teardownTimeout: 5000,
    globalSetup: ['./tests/setup/globalSetup.ts'],
    setupFiles: ['./tests/setup/testSetup.js'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,js}'],
      exclude: ['src/generated/**', 'src/migrations/**', 'src/stixpattern/**', 'src/python/**'],
      reporter: ['text', 'json', 'html'],
      clean: false,
    },
    maxWorkers: 1,
    isolate: false,
    sequence: {
      shuffle: false,
      sequencer: class Sequencer extends BaseSequencer {
        async shard(files: TestSpecification[]) {
          return files;
        }

        async sort(files: TestSpecification[]) {
          return files.sort((testA, testB) => (testA.moduleId > testB.moduleId ? 1 : -1));
        }
      },
    },
  },
});

export default buildIntegrationTestConfig(['(02|03|10|11|20|21|30|99)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
