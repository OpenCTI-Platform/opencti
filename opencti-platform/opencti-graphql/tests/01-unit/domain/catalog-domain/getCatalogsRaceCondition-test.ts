import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const FAKE_CONTEXT = {} as unknown as AuthContext;
const FAKE_USER = {} as unknown as AuthUser;

const validCatalogContent = (id: string) => JSON.stringify({
  id,
  name: 'Race Condition Test Catalog',
  description: 'Custom catalog used only for cache-stampede unit tests',
  contracts: [
    {
      title: 'Race Condition Test Connector',
      slug: 'race-condition-test-connector',
      manager_supported: false,
    },
  ],
});

let tmpDir: string;
let catalogFilePath: string;

const loadFreshCatalogDomain = async (customCatalogPaths: string[]) => {
  process.env.APP__CUSTOM_CATALOGS = JSON.stringify(customCatalogPaths);
  vi.resetModules();
  return import('../../../../src/modules/catalog/catalog-domain');
};

describe('catalog-domain - getCatalogs() / getSupportedContractsByImage() concurrency (cache stampede)', () => {
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'catalog-race-test-'));
    catalogFilePath = path.join(tmpDir, 'custom-catalog.json');
  });

  afterEach(() => {
    delete process.env.APP__CUSTOM_CATALOGS;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  afterAll(() => {
    vi.resetModules();
  });

  it('should return the exact same in-memory result across 20 concurrent calls mixing findCatalog() and getSupportedContractsByImage() (no duplicate build)', async () => {
    fs.writeFileSync(catalogFilePath, validCatalogContent('race-test-catalog-1'), 'utf8');
    const catalogDomain = await loadFreshCatalogDomain([catalogFilePath]);

    const calls = Array.from({ length: 20 }, (_, index) => (index % 2 === 0
      ? catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER)
      : catalogDomain.getSupportedContractsByImage()));

    const results = await Promise.all(calls);

    // getSupportedContractsByImage() is memoized as a single Promise<Map>,
    // so the exact same Map instance must be returned to every caller.
    const contractMaps = results.filter((_, index) => index % 2 === 1) as Map<string, unknown>[];
    contractMaps.forEach((map) => {
      expect(map).toBe(contractMaps[0]);
    });

    const catalogArrays = results.filter((_, index) => index % 2 === 0) as { id: string }[][];
    const firstCatalogRef = catalogArrays[0].find((c) => c.id === 'race-test-catalog-1');
    catalogArrays.forEach((catalogs) => {
      const catalogRef = catalogs.find((c) => c.id === 'race-test-catalog-1');
      expect(catalogRef).toBe(firstCatalogRef);
    });
  });

  it('should reuse the same in-flight build when getCatalogs() is triggered indirectly from two different entry points at once', async () => {
    fs.writeFileSync(catalogFilePath, validCatalogContent('race-test-catalog-2'), 'utf8');
    const catalogDomain = await loadFreshCatalogDomain([catalogFilePath]);

    // Cold start: both entry points race to trigger the very first build.
    const [catalogs, contractsByImage] = await Promise.all([
      catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER),
      catalogDomain.getSupportedContractsByImage(),
    ]);

    expect(catalogs.find((c) => c.id === 'race-test-catalog-2')).toBeDefined();
    expect(contractsByImage).toBeInstanceOf(Map);

    // A subsequent call from either entry point must still resolve to the
    // exact same underlying catalog object, proving there was only one build.
    const catalogsAgain = await catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER);
    expect(catalogsAgain.find((c) => c.id === 'race-test-catalog-2'))
      .toBe(catalogs.find((c) => c.id === 'race-test-catalog-2'));
  });

  it('should not read the catalog file again on a second sequential call (module-level cache)', async () => {
    fs.writeFileSync(catalogFilePath, validCatalogContent('race-test-catalog-3'), 'utf8');
    const catalogDomain = await loadFreshCatalogDomain([catalogFilePath]);

    const first = await catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER);
    const second = await catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER);

    expect(second.find((c) => c.id === 'race-test-catalog-3'))
      .toBe(first.find((c) => c.id === 'race-test-catalog-3'));
  });

  it('should rebuild (and reflect real file changes) after resetCatalogs()', async () => {
    fs.writeFileSync(catalogFilePath, validCatalogContent('race-test-catalog-4'), 'utf8');
    const catalogDomain = await loadFreshCatalogDomain([catalogFilePath]);

    const before = await catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER);
    const beforeRef = before.find((c) => c.id === 'race-test-catalog-4');
    expect(beforeRef).toBeDefined();

    catalogDomain.resetCatalogs();

    const after = await catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER);
    const afterRef = after.find((c) => c.id === 'race-test-catalog-4');

    // Same logical catalog, but a genuinely new object graph -> proves a real rebuild happened.
    expect(afterRef).toBeDefined();
    expect(afterRef).not.toBe(beforeRef);
    expect(afterRef).toEqual(beforeRef);
  });

  it('should allow a retry after a failed build instead of caching the rejection forever (real file deleted then recreated)', async () => {
    fs.writeFileSync(catalogFilePath, validCatalogContent('race-test-catalog-5'), 'utf8');
    const catalogDomain = await loadFreshCatalogDomain([catalogFilePath]);

    fs.unlinkSync(catalogFilePath);
    await expect(catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER)).rejects.toThrow();

    fs.writeFileSync(catalogFilePath, validCatalogContent('race-test-catalog-5'), 'utf8');

    const catalogs = await catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER);
    expect(catalogs.find((c) => c.id === 'race-test-catalog-5')).toBeDefined();
  });

  it('should not duplicate work when 20 concurrent calls race right after a resetCatalogs()', async () => {
    fs.writeFileSync(catalogFilePath, validCatalogContent('race-test-catalog-6'), 'utf8');
    const catalogDomain = await loadFreshCatalogDomain([catalogFilePath]);

    await catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER);
    catalogDomain.resetCatalogs();

    const results = await Promise.all(
      Array.from({ length: 20 }, () => catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER)),
    );

    const firstRef = results[0].find((c) => c.id === 'race-test-catalog-6');
    results.forEach((catalogs) => {
      expect(catalogs.find((c) => c.id === 'race-test-catalog-6')).toBe(firstRef);
    });
  });
});
