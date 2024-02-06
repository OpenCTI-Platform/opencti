/* eslint-disable import/no-extraneous-dependencies */
import { defineConfig } from 'vitest/config';
import graphql from '@rollup/plugin-graphql';
const buildTestConfig = (include) => defineConfig({
    plugins: [graphql()],
    test: {
        include,
        testTimeout: 300000,
        teardownTimeout: 20000,
        setupFiles: ['./tests/utils/testSetup.js'],
    },
});
export default buildTestConfig(['tests/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
