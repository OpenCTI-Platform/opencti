import { beforeEach, describe, expect, it, vi } from 'vitest';

const isFeatureEnabledMock = vi.fn();
const isCatalogManagerEnabledMock = vi.fn();
const findCatalogFromESMock = vi.fn();
const executionContextMock = vi.fn();
const confGetMock = vi.fn();

const SYSTEM_USER_MOCK = { id: 'system-user' } as any;

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: (...args: unknown[]) => confGetMock(...args),
    },
    isFeatureEnabled: (...args: unknown[]) => isFeatureEnabledMock(...args),
  };
});

vi.mock('../../../../src/manager/catalogManager', () => ({
  isCatalogManagerEnabled: (...args: unknown[]) => isCatalogManagerEnabledMock(...args),
}));

vi.mock('../../../../src/modules/catalog/catalog-repository', () => ({
  findCatalogFromES: (...args: unknown[]) => findCatalogFromESMock(...args),
}));

vi.mock('../../../../src/utils/access', () => ({
  executionContext: (...args: unknown[]) => executionContextMock(...args),
  SYSTEM_USER: SYSTEM_USER_MOCK,
}));

const DECOUPLING_CONNECTOR_VERSIONS = 'DECOUPLING_CONNECTOR_VERSIONS';

describe('catalog-domain auth fallback in ES mode', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    confGetMock.mockImplementation((key: string) => {
      if (key === 'app:custom_catalogs') return [];
      if (key === 'redis:ca') return [];
      return undefined;
    });

    isFeatureEnabledMock.mockImplementation((feature: string) => feature === DECOUPLING_CONNECTOR_VERSIONS);
    isCatalogManagerEnabledMock.mockReturnValue(true);

    const defaultContext = { source: 'catalog-domain', user: SYSTEM_USER_MOCK };
    executionContextMock.mockReturnValue(defaultContext);

    findCatalogFromESMock.mockResolvedValue([
      {
        id: 'catalog-contract-id',
        entity_type: 'Catalog',
        parent_types: ['Internal'],
        standard_id: 'catalog-contract-std-id',
        name: 'Ipinfo',
        description: 'Test catalog',
        contracts: [JSON.stringify({
          title: 'Ipinfo',
          slug: 'ipinfo',
          container_image: 'ghcr.io/opencti/ipinfo',
          container_version: '1.0.0',
        })],
      },
    ]);
  });

  it('uses system execution context when ES catalog is requested without explicit context/user', async () => {
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');

    const contracts = await catalogDomain.getSupportedContractsByImage();

    expect(executionContextMock).toHaveBeenCalledWith('catalog-domain', SYSTEM_USER_MOCK);
    expect(findCatalogFromESMock).toHaveBeenCalledWith(
      { source: 'catalog-domain', user: SYSTEM_USER_MOCK },
      SYSTEM_USER_MOCK,
    );
    expect(contracts.get('ghcr.io/opencti/ipinfo')).toEqual(expect.objectContaining({ slug: 'ipinfo' }));
  });

  it('uses provided context and explicit user when both are passed', async () => {
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');
    const providedUser = { id: 'explicit-user' } as any;
    const providedContext = { source: 'test-source', user: { id: 'context-user' } } as any;

    await catalogDomain.getSupportedContractsByImage(providedContext, providedUser);

    expect(executionContextMock).not.toHaveBeenCalled();
    expect(findCatalogFromESMock).toHaveBeenCalledWith(providedContext, providedUser);
  });

  it('uses provided context user when user argument is omitted', async () => {
    const catalogDomain = await import('../../../../src/modules/catalog/catalog-domain');
    const providedContextUser = { id: 'context-user' } as any;
    const providedContext = { source: 'test-source', user: providedContextUser } as any;

    await catalogDomain.getSupportedContractsByImage(providedContext);

    expect(executionContextMock).not.toHaveBeenCalled();
    expect(findCatalogFromESMock).toHaveBeenCalledWith(providedContext, providedContextUser);
  });
});
