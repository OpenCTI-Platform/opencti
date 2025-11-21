/* eslint-disable import/no-extraneous-dependencies */
import { buildTestConfig } from './vitest.config.test';

export default buildTestConfig(['tests/(01|02|03|04|05|06|07)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
// to run one test use yarn test:dev:init ; yarn test:dev:resume <test-name>
