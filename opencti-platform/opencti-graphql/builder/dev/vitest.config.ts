/* eslint-disable import/no-extraneous-dependencies */
import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';

export default defineConfig({
  plugins: [graphql()],
  test: {
    include: ['tests/(01|02|03|05)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    testTimeout: 1200000,
    setupFiles: ['tests/utils/testSetup.js'],
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
