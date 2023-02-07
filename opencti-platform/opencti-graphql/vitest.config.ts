/* eslint-disable import/no-extraneous-dependencies */
import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';
import type { PluginOption } from 'vite';
import vitestMigrationPlugin from './builder/plugin/vitestMigrationPlugin';

const buildTestConfig = (include: string[]) => defineConfig({
  plugins: [graphql() as PluginOption, vitestMigrationPlugin() as PluginOption],
  test: {
    include,
    testTimeout: 300000,
    teardownTimeout: 20000,
  },
});

export default buildTestConfig(['tests/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
