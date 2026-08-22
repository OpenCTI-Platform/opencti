import { beforeEach, describe, expect, it, vi } from 'vitest';

const findByIdMock = vi.fn();
const findCatalogMock = vi.fn();
const findContractBySlugMock = vi.fn();
const getCatalogVersionInfoMock = vi.fn();
const triggerRefreshInBackgroundMock = vi.fn();

vi.mock('../../../../src/modules/catalog/catalog-domain', () => ({
  findById: (...args: unknown[]) => findByIdMock(...args),
  findCatalog: (...args: unknown[]) => findCatalogMock(...args),
  findContractBySlug: (...args: unknown[]) => findContractBySlugMock(...args),
  getCatalogVersionInfo: (...args: unknown[]) => getCatalogVersionInfoMock(...args),
}));

vi.mock('../../../../src/manager/catalogManager', () => ({
  default: {
    triggerRefreshInBackground: (...args: unknown[]) => triggerRefreshInBackgroundMock(...args),
  },
}));

const invokeResolver = async (
  resolverEntry: unknown,
  parent: unknown,
  args: unknown,
  context: unknown,
  info: unknown,
) => {
  if (typeof resolverEntry === 'function') {
    return resolverEntry(parent, args, context, info);
  }
  if (
    resolverEntry
    && typeof resolverEntry === 'object'
    && 'resolve' in resolverEntry
    && typeof (resolverEntry as { resolve: unknown }).resolve === 'function'
  ) {
    return (resolverEntry as { resolve: (p: unknown, a: unknown, c: unknown, i: unknown) => unknown })
      .resolve(parent, args, context, info);
  }
  throw new Error('Resolver is not callable');
};

describe('catalog-resolver', () => {
  beforeEach(() => {
    findByIdMock.mockReset();
    findCatalogMock.mockReset();
    findContractBySlugMock.mockReset();
    getCatalogVersionInfoMock.mockReset();
    triggerRefreshInBackgroundMock.mockReset();
  });

  it('maps Query.catalog to findById', async () => {
    const { default: resolver } = await import('../../../../src/modules/catalog/catalog-resolver');
    const context = { user: { id: 'u1' } } as any;

    findByIdMock.mockResolvedValue({ id: 'catalog-1' });

    const result = await invokeResolver(resolver.Query?.catalog, {}, { id: 'catalog-1' }, context, {});

    expect(findByIdMock).toHaveBeenCalledWith(context, context.user, 'catalog-1');
    expect(result).toEqual({ id: 'catalog-1' });
  });

  it('maps Query.catalogs to findCatalog', async () => {
    const { default: resolver } = await import('../../../../src/modules/catalog/catalog-resolver');
    const context = { user: { id: 'u1' } } as any;

    findCatalogMock.mockResolvedValue([{ id: 'catalog-1' }]);

    const result = await invokeResolver(resolver.Query?.catalogs, {}, {}, context, {});

    expect(findCatalogMock).toHaveBeenCalledWith(context, context.user);
    expect(result).toEqual([{ id: 'catalog-1' }]);
  });

  it('maps Query.catalogVersionInfo to getCatalogVersionInfo', async () => {
    const { default: resolver } = await import('../../../../src/modules/catalog/catalog-resolver');

    getCatalogVersionInfoMock.mockReturnValue({ status: 'ready', revision: 'r1', updated_at: 'now' });

    const result = await invokeResolver(resolver.Query?.catalogVersionInfo, {}, {}, {}, {});

    expect(getCatalogVersionInfoMock).toHaveBeenCalled();
    expect(result).toEqual({ status: 'ready', revision: 'r1', updated_at: 'now' });
  });

  it('maps Query.contract to findContractBySlug', async () => {
    const { default: resolver } = await import('../../../../src/modules/catalog/catalog-resolver');
    const context = { user: { id: 'u1' } } as any;

    findContractBySlugMock.mockResolvedValue({ catalog_id: 'catalog-1', contract: '{}' });

    const result = await invokeResolver(resolver.Query?.contract, {}, { slug: 'ipinfo' }, context, {});

    expect(findContractBySlugMock).toHaveBeenCalledWith(context, context.user, 'ipinfo');
    expect(result).toEqual({ catalog_id: 'catalog-1', contract: '{}' });
  });

  it('maps Mutation.refreshCatalog to triggerRefreshInBackground and returns true', async () => {
    const { default: resolver } = await import('../../../../src/modules/catalog/catalog-resolver');

    const result = await invokeResolver(resolver.Mutation?.refreshCatalog, {}, {}, {}, {});

    expect(triggerRefreshInBackgroundMock).toHaveBeenCalled();
    expect(result).toBe(true);
  });
});
