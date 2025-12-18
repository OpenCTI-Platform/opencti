import { buildIntegrationTestConfig } from './vitest.config.integration';

export default buildIntegrationTestConfig(['tests/(02|20|30|99)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);
