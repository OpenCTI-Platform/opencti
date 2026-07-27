import { beforeEach, describe, expect, it, vi } from 'vitest';

const isFeatureEnabledMock = vi.fn();

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: vi.fn(() => []),
    },
    isFeatureEnabled: (...args: unknown[]) => isFeatureEnabledMock(...args),
    logApp: {
      ...actual.logApp,
      info: vi.fn(),
      warn: vi.fn(),
      debug: vi.fn(),
    },
  };
});

describe('catalog-domain decoupling helpers', () => {
  beforeEach(() => {
    vi.resetModules();
    isFeatureEnabledMock.mockReset();
  });

  it('returns ready/null version info when feature flag is disabled', async () => {
    isFeatureEnabledMock.mockReturnValue(false);
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');

    expect(catalogDomain.getCatalogStatus()).toBe('ready');
    expect(catalogDomain.getCatalogVersionInfo()).toEqual({
      status: 'ready',
      revision: null,
      updated_at: null,
    });
  });

  it('stores status and revision when manager cache is updated', async () => {
    isFeatureEnabledMock.mockReturnValue(true);
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');

    const internalCatalog = {
      catalogMap: {},
      contractsByImage: new Map(),
      allContracts: [],
      contractsBySlug: new Map(),
      latestContractsBySlug: new Map(),
    } as any;

    catalogDomain.updateCatalogManagerInternalCache(internalCatalog, 'ready', false, 'rev-123');

    expect(catalogDomain.getCatalogStatus()).toBe('ready');
    expect(catalogDomain.getCatalogVersionInfo().revision).toBe('rev-123');
    expect(catalogDomain.getCatalogVersionInfo().updated_at).toBeTypeOf('string');
  });

  it('keeps existing snapshot when keepExistingSnapshot=true', async () => {
    isFeatureEnabledMock.mockReturnValue(true);
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');

    const firstSnapshot = {
      catalogMap: {},
      contractsByImage: new Map(),
      allContracts: [],
      contractsBySlug: new Map(),
      latestContractsBySlug: new Map(),
    } as any;

    catalogDomain.updateCatalogManagerInternalCache(firstSnapshot, 'ready', false, 'rev-a');
    catalogDomain.updateCatalogManagerInternalCache(undefined, 'error', true, 'rev-b');

    expect(catalogDomain.getCatalogManagerInternalCache()).toBe(firstSnapshot);
    expect(catalogDomain.getCatalogVersionInfo().status).toBe('error');
    expect(catalogDomain.getCatalogVersionInfo().revision).toBe('rev-b');
  });

  it('returns grouped/latest contracts from manager cache when decoupling is enabled', async () => {
    isFeatureEnabledMock.mockReturnValue(true);
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');

    const ipinfoV1 = { slug: 'ipinfo', container_version: '1.0.0' };
    const ipinfoV2 = { slug: 'ipinfo', container_version: '1.1.0' };
    const shodanV1 = { slug: 'shodan', container_version: '2.0.0' };

    const grouped = new Map([
      ['ipinfo', [ipinfoV1, ipinfoV2]],
      ['shodan', [shodanV1]],
    ]);
    const latest = new Map([
      ['ipinfo', ipinfoV2],
      ['shodan', shodanV1],
    ]);

    const internalCatalog = {
      catalogMap: {},
      contractsByImage: new Map(),
      allContracts: [ipinfoV1, ipinfoV2, shodanV1],
      contractsBySlug: grouped,
      latestContractsBySlug: latest,
    } as any;

    catalogDomain.updateCatalogManagerInternalCache(internalCatalog, 'ready', false, 'rev-contracts');

    const allContracts = await catalogDomain.getAllConnectorContracts();
    const contractsBySlug = await catalogDomain.getContractsBySlug();
    const latestBySlug = await catalogDomain.getLatestContractsBySlug();
    const latestIpinfo = await catalogDomain.findLatestContractBySlug('ipinfo');

    expect(allContracts).toHaveLength(3);
    expect(contractsBySlug.get('ipinfo')).toHaveLength(2);
    expect(latestBySlug.get('ipinfo')).toBe(ipinfoV2);
    expect(latestIpinfo).toBe(ipinfoV2);
  });
});
