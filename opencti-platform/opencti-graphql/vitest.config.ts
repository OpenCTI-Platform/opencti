import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';

export const buildTestConfig = (include: string[]) => defineConfig({
  plugins: [graphql()],
  test: {
    dir: './tests',
    include,
    testTimeout: 300000,
    teardownTimeout: 5000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,js}'],
      exclude: ['src/generated/**', 'src/migrations/**', 'src/stixpattern/**', 'src/python/**'],
      reporter: ['text', 'json', 'html'],
      clean: false,
    },
  },
});

export default buildTestConfig(['**/*-test.{ts,js}']);
