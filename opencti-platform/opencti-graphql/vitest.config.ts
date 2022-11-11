/* eslint-disable import/no-extraneous-dependencies */
import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';

export default defineConfig({
  plugins: [graphql()],
  test: {
    include: ['tests/**/*.test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    setupFiles: ['./tests/utils/testSetup.js'],
    coverage: {
      provider: 'istanbul',
      reporter: ['text', 'json', 'html'],
    },
    sequence: {
      shuffle: false,
      sequencer: class Sequencer {
        // eslint-disable-next-line class-methods-use-this
        async shard(files: string[]): Promise<string[]> {
          return files;
        }

        // eslint-disable-next-line class-methods-use-this
        async sort(files: string[]): Promise<string[]> {
          return files.sort((testA, testB) => (testA > testB ? 1 : -1));
        }
      },
    },
  },
});
