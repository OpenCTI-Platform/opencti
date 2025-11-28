 
import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';
import type { PluginOption } from 'vite';

export const buildTestConfig = (include: string[]) => defineConfig({
  plugins: [graphql() as PluginOption],
  test: {
    include,
    testTimeout: 300000,
    teardownTimeout: 20000,
    setupFiles: ['./tests/utils/testSetup.js'],
  },
});

export default buildTestConfig(['tests/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
