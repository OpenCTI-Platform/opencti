/* eslint-disable import/no-extraneous-dependencies */
import { buildTestConfig } from './vitest.config.test';

export default buildTestConfig(['tests/(01|02|03|05|06)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
// export default buildTestConfig(['tests/(02)-*/**/(loader|filterGroup|grouping|workspace)*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
