/* eslint-disable import/no-extraneous-dependencies */
import { buildTestConfig } from './vitest.config.test';

export default buildTestConfig(['tests/*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
// to run one test use yarn test:dev:init ; yarn test:dev:resume <test-name>
