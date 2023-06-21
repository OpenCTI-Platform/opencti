/* eslint-disable import/no-extraneous-dependencies */
import { buildTestConfig } from './vitest.config.test';

// TODO: rollback the real configuration
export default buildTestConfig(['tests/02-*/04-*/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
