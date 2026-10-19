import { buildIntegrationTestConfig } from './vitest.config.integration';

export default buildIntegrationTestConfig(['(02|20|21|30|99)-*/**/*-test.{ts,js}']);
