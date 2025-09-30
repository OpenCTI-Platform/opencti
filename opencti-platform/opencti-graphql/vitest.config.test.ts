/* eslint-disable import/no-extraneous-dependencies */
import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';
import type { PluginOption } from 'vite';
import { BaseSequencer, type TestSpecification } from 'vitest/node';

export const buildTestConfig = (include: string[]) => defineConfig({
  plugins: [graphql() as PluginOption],
  test: {
    include,
    testTimeout: 1200000,
    teardownTimeout: 5000,
    globalSetup: ['./tests/utils/globalSetup.ts'],
    setupFiles: ['./tests/utils/testSetup.js'],
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      exclude: ['src/generated/**', 'src/migrations/**', 'src/stixpattern/**', 'src/python/**'],
      reporter: ['text', 'json', 'html'],
    },
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
    sequence: {
      shuffle: false,
      sequencer: class Sequencer extends BaseSequencer {
        // eslint-disable-next-line class-methods-use-this
        async shard(files: TestSpecification[]) {
          return files;
        }

        // eslint-disable-next-line class-methods-use-this
        async sort(files: TestSpecification[]) {
          return files.sort((testA, testB) => (testA.moduleId > testB.moduleId ? 1 : -1));
        }
      },
    },
  },
});

export default buildTestConfig(['tests/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
