import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockFindLatestCompatibleCatalogContractBySlug } = vi.hoisted(() => ({
  mockFindLatestCompatibleCatalogContractBySlug: vi.fn(),
}));

vi.mock('../../../../src/modules/catalog/catalog-repository', () => ({
  findCatalogContractsByImageName: vi.fn(),
  findCatalogContractsBySlugs: vi.fn(),
  findLatestCompatibleCatalogContractByImageName: vi.fn(),
  findLatestCompatibleCatalogContractBySlug: mockFindLatestCompatibleCatalogContractBySlug,
}));

import { findLatestCompatibleCatalogContractBySlug } from '../../../../src/modules/catalog/catalog-api';
import { buildErrorScope, tagErrorModule } from '../../../../src/config/error-origin';
import { FunctionalError, InfraError } from '../../../../src/config/errors';

const context = {} as any;
const user = {} as any;

// The connector module calls the catalog, as its auto-upgrade does.
const failureSeenByConnector = async () => {
  const error = await findLatestCompatibleCatalogContractBySlug(context, user, 'slug').catch((e: unknown) => e);
  return buildErrorScope(error, 'connector');
};

describe('catalog public API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should attribute a bug raised in the catalog to the catalog', async () => {
    mockFindLatestCompatibleCatalogContractBySlug.mockRejectedValue(new TypeError('x is undefined'));
    expect(await failureSeenByConnector()).toEqual({ origin: 'code', module: 'catalog', entry_module: 'connector' });
  });

  it('should keep a rejection of the catalog as input', async () => {
    mockFindLatestCompatibleCatalogContractBySlug.mockRejectedValue(FunctionalError('Catalog contracts not found'));
    expect(await failureSeenByConnector()).toEqual({ origin: 'input', module: 'catalog', entry_module: 'connector' });
  });

  it('should attribute an unavailable dependency of the catalog to the catalog', async () => {
    mockFindLatestCompatibleCatalogContractBySlug.mockRejectedValue(InfraError('elasticsearch'));
    expect(await failureSeenByConnector()).toEqual({ origin: 'infra', dependency: 'elasticsearch', module: 'catalog', entry_module: 'connector' });
  });

  it('should keep the tag of the shared code the catalog went through', async () => {
    mockFindLatestCompatibleCatalogContractBySlug.mockRejectedValue(tagErrorModule(new TypeError('bug in a shared client'), 'core'));
    expect(await failureSeenByConnector()).toEqual({ origin: 'code', module: 'core', entry_module: 'connector' });
  });

  it('should return the result untouched', async () => {
    mockFindLatestCompatibleCatalogContractBySlug.mockResolvedValue({ slug: 'slug' });
    await expect(findLatestCompatibleCatalogContractBySlug(context, user, 'slug')).resolves.toEqual({ slug: 'slug' });
  });
});
