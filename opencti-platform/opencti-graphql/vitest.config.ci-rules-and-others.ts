import { buildIntegrationTestConfig } from './vitest.config.integration';

export default buildIntegrationTestConfig(['tests/(02|05|06|07)-*/**/*-test.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']);