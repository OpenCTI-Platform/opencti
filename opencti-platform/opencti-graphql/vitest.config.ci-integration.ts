/* eslint-disable import/no-extraneous-dependencies */
import { buildTestConfig } from './vitest.config.test';

export default buildTestConfig(['tests/(02|03|04)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);