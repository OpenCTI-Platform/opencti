import { beforeEach, describe, expect, it, vi } from 'vitest';

const isFeatureEnabledMock = vi.fn();
const isCatalogManagerEnabledMock = vi.fn();
const getCatalogVersionInfoMock = vi.fn();

const findCatalogFromESMock = vi.fn();
const findCatalogMock = vi.fn();
const findByIdMock = vi.fn();
const findContractBySlugMock = vi.fn();

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  return {
    ...actual,
    isFeatureEnabled: (...args: unknown[]) => isFeatureEnabledMock(...args),
  };
});

vi.mock('../../../../src/modules/catalog/catalogManager', () => ({
  isCatalogManagerEnabled: (...args: unknown[]) => isCatalogManagerEnabledMock(...args),
  getCatalogVersionInfo: (...args: unknown[]) => getCatalogVersionInfoMock(...args),
}));

vi.mock('../../../../src/modules/catalog/catalog-repository', () => ({
  findCatalogFromES: (...args: unknown[]) => findCatalogFromESMock(...args),
}));

vi.mock('../../../../src/modules/catalog/catalog-domain', () => ({
  findCatalog: (...args: unknown[]) => findCatalogMock(...args),
  findById: (...args: unknown[]) => findByIdMock(...args),
  findContractBySlug: (...args: unknown[]) => findContractBySlugMock(...args),
}));

import catalogResolver from '../../../../src/modules/catalog/catalog-resolver';

const DECOUPLING_CONNECTOR_VERSIONS = 'DECOUPLING_CONNECTOR_VERSIONS';
const mockContext = { user: { id: 'user-1' } } as any;
const queryResolvers = catalogResolver.Query as NonNullable<typeof catalogResolver.Query>;

const invokeQueryResolver = async (
  resolver: unknown,
  args: Record<string, unknown> = {},
  context: unknown = mockContext,
) => {
  if (typeof resolver === 'function') {
    return resolver({}, args, context, {} as any);
  }
  if (resolver && typeof resolver === 'object' && 'resolve' in resolver && typeof resolver.resolve === 'function') {
    return resolver.resolve({}, args, context, {} as any);
  }
  throw new TypeError('Query resolver is not callable');
};

describe('catalog-resolver routing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getCatalogVersionInfoMock.mockReturnValue({ status: 'ready', revision: null, updated_at: null });
    findCatalogFromESMock.mockResolvedValue([{ id: 'es-catalog' }]);
    findCatalogMock.mockResolvedValue([{ id: 'legacy-catalog' }]);
    findByIdMock.mockResolvedValue({ id: 'legacy-by-id' });
    findContractBySlugMock.mockResolvedValue({ catalog_id: 'legacy-catalog', contract: '{}' });
  });

  it('uses legacy embedded path when FF is off', async () => {
    isFeatureEnabledMock.mockImplementation((feature: string) => feature === DECOUPLING_CONNECTOR_VERSIONS ? false : false);
    isCatalogManagerEnabledMock.mockReturnValue(true);

    const result = await invokeQueryResolver(queryResolvers.catalogs);

    expect(findCatalogMock).toHaveBeenCalledWith(mockContext, mockContext.user);
    expect(findCatalogFromESMock).not.toHaveBeenCalled();
    expect(result).toEqual([{ id: 'legacy-catalog' }]);
  });

  it('uses legacy embedded path when FF is on and catalog manager is off', async () => {
    isFeatureEnabledMock.mockImplementation((feature: string) => feature === DECOUPLING_CONNECTOR_VERSIONS);
    isCatalogManagerEnabledMock.mockReturnValue(false);

    const result = await invokeQueryResolver(queryResolvers.catalogs);

    expect(findCatalogMock).toHaveBeenCalledWith(mockContext, mockContext.user);
    expect(findCatalogFromESMock).not.toHaveBeenCalled();
    expect(result).toEqual([{ id: 'legacy-catalog' }]);
  });

  it('uses ES path for catalogs when FF is on and catalog manager is on', async () => {
    isFeatureEnabledMock.mockImplementation((feature: string) => feature === DECOUPLING_CONNECTOR_VERSIONS);
    isCatalogManagerEnabledMock.mockReturnValue(true);

    const result = await invokeQueryResolver(queryResolvers.catalogs);

    expect(findCatalogFromESMock).toHaveBeenCalledWith(mockContext, mockContext.user);
    expect(findCatalogMock).not.toHaveBeenCalled();
    expect(result).toEqual([{ id: 'es-catalog' }]);
  });

  it('keeps catalog(id) and contract(slug) on legacy domain path for now', async () => {
    isFeatureEnabledMock.mockImplementation((feature: string) => feature === DECOUPLING_CONNECTOR_VERSIONS);
    isCatalogManagerEnabledMock.mockReturnValue(true);

    await invokeQueryResolver(queryResolvers.catalog, { id: 'catalog-id' });
    await invokeQueryResolver(queryResolvers.contract, { slug: 'ipinfo' });

    expect(findByIdMock).toHaveBeenCalledWith(mockContext, mockContext.user, 'catalog-id');
    expect(findContractBySlugMock).toHaveBeenCalledWith(mockContext, mockContext.user, 'ipinfo');
  });

  it('exposes catalogVersionInfo from manager', async () => {
    getCatalogVersionInfoMock.mockReturnValue({ status: 'ready', revision: 'etag-1', updated_at: '2026-07-29T09:00:00.000Z' });

    const result = await invokeQueryResolver(queryResolvers.catalogVersionInfo);

    expect(result).toEqual({ status: 'ready', revision: 'etag-1', updated_at: '2026-07-29T09:00:00.000Z' });
  });
});
