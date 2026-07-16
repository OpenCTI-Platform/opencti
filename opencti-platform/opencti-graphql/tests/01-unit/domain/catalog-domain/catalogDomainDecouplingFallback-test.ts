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

  it('uses embedded catalog as baseline while manager status is loading', async () => {
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');

    catalogDomain.resetCatalogs();

    const catalogs = await catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER);
    const contractsByImage = await catalogDomain.getSupportedContractsByImage();

    // Embedded catalog is always the baseline — connectors get data immediately.
    expect(catalogs.length).toBeGreaterThan(0);
    expect(contractsByImage.size).toBeGreaterThan(0);
  });

  it('uses embedded catalog as baseline while manager status is error', async () => {
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');

    catalogDomain.resetCatalogs();
    catalogDomain.updateCatalogManagerInternalCache(undefined, 'error');

    const catalogs = await catalogDomain.findCatalog(FAKE_CONTEXT, FAKE_USER);
    const contractsByImage = await catalogDomain.getSupportedContractsByImage();

    expect(catalogs.length).toBeGreaterThan(0);
    expect(contractsByImage.size).toBeGreaterThan(0);
  });

  // ── scenario: load → reduced catalog (revision changes) ────────────────────
  it('returns updated catalog and new revision after manager writes a new snapshot', async () => {
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');
    catalogDomain.resetCatalogs();

    const fakeContract = {
      title: 'Reduced Connector',
      slug: 'reduced-connector',
      description: '',
      short_description: '',
      logo: '',
      use_cases: [],
      verified: false,
      last_verified_date: '2026-01-01',
      playbook_supported: false,
      max_confidence_level: 100,
      support_version: '1.0.0',
      subscription_link: '',
      source_code: '',
      manager_supported: true,
      container_version: '1.0.0',
      container_image: 'ghcr.io/test/reduced:1.0.0',
      container_type: 'EXTERNAL_IMPORT',
      config_schema: {
        $schema: 'http://json-schema.org/draft-07/schema#',
        $id: 'reduced-config',
        type: 'object',
        properties: {},
        required: [],
        additionalProperties: false,
      },
    };

    const { buildInternalCatalog } = await import('../../../../src/modules/catalog/catalog-cache');
    const internalCatalog = buildInternalCatalog([{
      id: 'reduced-catalog',
      name: 'Reduced',
      description: '',
      contracts: [fakeContract],
    }]);

    catalogDomain.updateCatalogManagerInternalCache(internalCatalog, 'ready', false, 'revision-reduced');

    const versionInfo = catalogDomain.getCatalogVersionInfo();
    expect(versionInfo.status).toBe('ready');
    expect(versionInfo.revision).toBe('revision-reduced');

    const contracts = await catalogDomain.getSupportedContractsByImage();
    expect(contracts.has('ghcr.io/test/reduced:1.0.0')).toBe(true);
  });

  // ── scenario: error → recover (status and revision update) ─────────────────
  it('reflects error status then recovers to ready with a new revision', async () => {
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');
    catalogDomain.resetCatalogs();

    // Inject error (keeps existing snapshot = true, so snapshot stays undefined here)
    catalogDomain.updateCatalogManagerInternalCache(undefined, 'error', true);
    expect(catalogDomain.getCatalogVersionInfo().status).toBe('error');

    // Recover: write a new catalog
    const { buildInternalCatalog } = await import('../../../../src/modules/catalog/catalog-cache');
    const recovered = buildInternalCatalog([{ id: 'r', name: 'R', description: '', contracts: [] }]);
    catalogDomain.updateCatalogManagerInternalCache(recovered, 'ready', false, 'revision-after-recovery');

    const info = catalogDomain.getCatalogVersionInfo();
    expect(info.status).toBe('ready');
    expect(info.revision).toBe('revision-after-recovery');
  });

  // ── scenario: loading status → empty catalogs ───────────────────────────────
  it('getCatalogVersionInfo returns loading status before manager first run', async () => {
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');
    catalogDomain.resetCatalogs();

    const info = catalogDomain.getCatalogVersionInfo();
    expect(info.status).toBe('loading');
    expect(info.revision).toBeNull();
  });
});
