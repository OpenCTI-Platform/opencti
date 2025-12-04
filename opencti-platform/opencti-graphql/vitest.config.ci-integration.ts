import { buildIntegrationTestConfig } from './vitest.config.integration';

export default buildIntegrationTestConfig(['tests/(02|03|04)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);