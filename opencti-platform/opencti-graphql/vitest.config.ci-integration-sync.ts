import { buildIntegrationTestConfig } from './vitest.config.integration';

export default buildIntegrationTestConfig(['(02|03|10|11|21)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
