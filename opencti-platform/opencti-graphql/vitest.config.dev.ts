/* eslint-disable import/no-extraneous-dependencies */
import { buildTestConfig } from './vitest.config';

export default buildTestConfig(['tests/(01|02|03|05)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
