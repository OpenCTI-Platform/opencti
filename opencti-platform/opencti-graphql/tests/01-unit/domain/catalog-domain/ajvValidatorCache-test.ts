import { fileURLToPath } from 'node:url';
import Ajv from 'ajv';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { CatalogContract } from '../../../../src/modules/catalog/catalog-types';
import type { ConnectorContractConfiguration } from '../../../../src/generated/graphql';

const compileSpy = vi.spyOn(Ajv.prototype, 'compile');

const TEST_CATALOG_URL = new URL('../../../utils/opencti-manifest.json', import.meta.url);

let catalogDomain: typeof import('../../../../src/modules/catalog/catalog-domain');

const buildContract = (overrides: Partial<CatalogContract> = {}): CatalogContract => ({
  title: 'IPinfo',
  slug: 'ipinfo',
  description: 'test',
  container_image: 'opencti/connector-ipinfo',
  container_type: 'EXTERNAL_IMPORT',
  manager_supported: true,
  config_schema: {
    type: 'object',
    properties: {
      IPINFO_TOKEN: { type: 'string' },
      CONNECTOR_LOG_LEVEL: { type: 'string' },
      CONNECTOR_SCOPE: { type: 'array', items: { type: 'string' } },
    },
    required: ['IPINFO_TOKEN'],
    additionalProperties: false,
  },
  ...overrides,
} as unknown as CatalogContract);

const buildConfig = (entries: Record<string, string>): ConnectorContractConfiguration[] => Object.entries(entries).map(([key, value]) => ({ key, value }));

describe('catalog-domain - AJV validator compilation cache', () => {
  beforeAll(async () => {
    process.env.APP__CUSTOM_CATALOGS = JSON.stringify([fileURLToPath(TEST_CATALOG_URL)]);
    vi.resetModules();
    catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');
  });

  afterAll(() => {
    delete process.env.APP__CUSTOM_CATALOGS;
  });

  beforeEach(() => {
    catalogDomain.resetCatalogs();
    compileSpy.mockClear();
  });

  afterEach(() => {
    compileSpy.mockClear();
  });

  it('should compile the validator only ONCE for N calls sharing the exact same configuration shape', () => {
    const contract = buildContract();
    const config = buildConfig({ IPINFO_TOKEN: 'token-value' });

    for (let i = 0; i < 10; i += 1) {
      catalogDomain.validateContractConfigurations(config, contract);
    }

    expect(compileSpy).toHaveBeenCalledTimes(1);
  });

  it('should compile a NEW validator when an optional field changes the shape (different cache key)', () => {
    const contract = buildContract();

    catalogDomain.validateContractConfigurations(
      buildConfig({ IPINFO_TOKEN: 'token-value' }),
      contract,
    );
    expect(compileSpy).toHaveBeenCalledTimes(1);

    // Adding an optional field present in the payload changes `validationProperties`,
    // hence the cacheKey, hence a real new compile is expected.
    catalogDomain.validateContractConfigurations(
      buildConfig({ IPINFO_TOKEN: 'token-value', CONNECTOR_LOG_LEVEL: 'debug' }),
      contract,
    );
    expect(compileSpy).toHaveBeenCalledTimes(2);

    // Replaying the first shape again must NOT trigger a third compile.
    catalogDomain.validateContractConfigurations(
      buildConfig({ IPINFO_TOKEN: 'token-value-2' }),
      contract,
    );
    expect(compileSpy).toHaveBeenCalledTimes(2);
  });

  it('should invalidate the validator cache on resetCatalogs()', () => {
    const contract = buildContract();
    const config = buildConfig({ IPINFO_TOKEN: 'token-value' });

    catalogDomain.validateContractConfigurations(config, contract);
    expect(compileSpy).toHaveBeenCalledTimes(1);

    catalogDomain.resetCatalogs();

    catalogDomain.validateContractConfigurations(config, contract);
    expect(compileSpy).toHaveBeenCalledTimes(2);
  });

  it('should throw a formatted validation error without caching a broken state', () => {
    const contract = buildContract();

    expect(() => catalogDomain.validateContractConfigurations(
      buildConfig({}),
      contract,
    )).toThrow(/Missing required field/);

    expect(compileSpy).toHaveBeenCalledTimes(1);

    catalogDomain.validateContractConfigurations(
      buildConfig({ IPINFO_TOKEN: 'token-value' }),
      contract,
    );
    expect(compileSpy).toHaveBeenCalledTimes(1);
  });

  it('should not force recompilation of already-cached shapes after many distinct cache entries', () => {
    const knownShapesCount = 20;
    const knownContracts = Array.from({ length: knownShapesCount }, (_, i) => buildContract({
      title: `known-contract-${i}`,
      slug: `known-contract-${i}`,
    }));

    // 1) Warm up the cache with a first batch of distinct, "already known" shapes.
    knownContracts.forEach((contract) => {
      catalogDomain.validateContractConfigurations(
        buildConfig({ IPINFO_TOKEN: 'token-value' }),
        contract,
      );
    });
    expect(compileSpy).toHaveBeenCalledTimes(knownShapesCount);

    // 2) Push the cache with many brand new distinct shapes.
    const overflowCount = 550;
    for (let i = 0; i < overflowCount; i += 1) {
      const overflowContract = buildContract({
        title: `overflow-contract-${i}`,
        slug: `overflow-contract-${i}`,
      });
      catalogDomain.validateContractConfigurations(
        buildConfig({ IPINFO_TOKEN: 'token-value' }),
        overflowContract,
      );
    }
    compileSpy.mockClear();

    // 3) Replay the ORIGINAL known shapes. A blanket `.clear()` on overflow would force
    // ALL of them to recompile here. A bounded/eviction-safe implementation should
    // recompile few or none of them (ideally 0, since they were the "hottest"/earliest
    // entries - acceptable tolerance left for a legitimate LRU eviction strategy).
    knownContracts.forEach((contract) => {
      catalogDomain.validateContractConfigurations(
        buildConfig({ IPINFO_TOKEN: 'token-value' }),
        contract,
      );
    });

    const extraCompilesOnReplay = compileSpy.mock.calls.length;
    expect(extraCompilesOnReplay).toBeLessThan(knownShapesCount);
  });
});
