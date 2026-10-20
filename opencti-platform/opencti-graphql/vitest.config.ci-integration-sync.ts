import { buildIntegrationTestConfig } from './vitest.config.integration';

export default buildIntegrationTestConfig(['(02|03|10|11)-*/**/*-test.{ts,js}']);
