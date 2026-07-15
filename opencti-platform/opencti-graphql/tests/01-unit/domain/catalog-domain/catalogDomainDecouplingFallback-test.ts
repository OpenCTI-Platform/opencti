import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const FAKE_CONTEXT = {} as unknown as AuthContext;
const FAKE_USER = {} as unknown as AuthUser;

describe('catalog-domain decoupling fallback policy', () => {
  beforeEach(() => {
    process.env.APP__ENABLED_DEV_FEATURES = JSON.stringify(['DECOUPLING_CONNECTOR_VERSIONS']);
    process.env.APP__CUSTOM_CATALOGS = JSON.stringify([]);
    vi.resetModules();
  });

  afterEach(() => {
    delete process.env.APP__ENABLED_DEV_FEATURES;
    delete process.env.APP__CUSTOM_CATALOGS;
  });

  it('does not fallback to legacy catalog while manager status is loading', async () => {
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');

    catalogDomain.resetCatalogs();

    const catalogs = await catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER);
    const contractsByImage = await catalogDomain.getSupportedContractsByImage();

    expect(catalogs).toEqual([]);
    expect(contractsByImage.size).toBe(0);
  });

  it('falls back to legacy catalog only when manager status is error', async () => {
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');

    catalogDomain.resetCatalogs();
    catalogDomain.updateCatalogManagerInternalCache(undefined, 'error');

    const catalogs = await catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER);

    expect(catalogs.length).toBeGreaterThan(0);
  });
});
