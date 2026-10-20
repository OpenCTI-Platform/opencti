import { buildIntegrationTestConfig } from './vitest.config.integration';

// Ingestion benchmark scenarios, run through benchmarks/ingestion/run.py (see its README)
export default buildIntegrationTestConfig(['bench/scenarios/*.scenario.ts']);
