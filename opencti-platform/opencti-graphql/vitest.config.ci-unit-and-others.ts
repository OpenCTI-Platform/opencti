/* eslint-disable import/no-extraneous-dependencies */
import { buildTestConfig } from './vitest.config.test';

export default buildTestConfig(['tests/(01|O7)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);