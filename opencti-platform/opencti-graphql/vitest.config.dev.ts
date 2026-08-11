import { buildIntegrationTestConfig } from './vitest.config.integration';

export default buildIntegrationTestConfig(['**/*-test.{ts,js}']);
// to run one test use yarn test:dev:init ; yarn test:dev:resume <test-name>
