 import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';
import type { PluginOption } from 'vite';

export const buildTestConfig = (include: string[]) => defineConfig({
  plugins: [graphql() as PluginOption],
  test: {
    include,
    testTimeout: 300000,
    teardownTimeout: 5000,
    setupFiles: [],
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      exclude: ['src/generated/**', 'src/migrations/**', 'src/stixpattern/**', 'src/python/**'],
      reporter: ['text', 'json', 'html'],
    },
    maxWorkers: 10,
  },
});

export default buildTestConfig(['tests/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
