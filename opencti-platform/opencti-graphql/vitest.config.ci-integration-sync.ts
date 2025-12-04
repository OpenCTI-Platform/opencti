 import { buildIntegrationTestConfig } from './vitest.config.integration';

export default buildIntegrationTestConfig(['tests/(02|03|10|11)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
