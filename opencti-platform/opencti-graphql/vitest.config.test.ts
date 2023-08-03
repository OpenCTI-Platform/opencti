/* eslint-disable import/no-extraneous-dependencies */
import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';
import type { PluginOption } from 'vite';
import vitestMigrationPlugin from './builder/plugin/vitestMigrationPlugin';
import type { TestSequencer, WorkspaceSpec } from 'vitest/node';

export const buildTestConfig = (include: string[]) => defineConfig({
  plugins: [graphql() as PluginOption, vitestMigrationPlugin() as PluginOption],
  test: {
    include,
    testTimeout: 1200000,
    teardownTimeout: 20000,
    globalSetup: ['./tests/utils/globalSetup.js'],
    setupFiles: ['./tests/utils/testSetup.js'],
    coverage: {
      provider: 'istanbul',
      reporter: ['text', 'json', 'html'],
    },
    sequence: {
      shuffle: false,
      sequencer: class Sequencer implements TestSequencer {
        // eslint-disable-next-line class-methods-use-this
        async shard(files: WorkspaceSpec[]): Promise<WorkspaceSpec[]> {
          return files;
        }

        // eslint-disable-next-line class-methods-use-this
        async sort(files: WorkspaceSpec[]): Promise<WorkspaceSpec[]> {
          return files.sort((testA, testB) => (testA > testB ? 1 : -1));
        }
      },
    },
  },
});

export default buildTestConfig(['tests/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
