import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ENTITY_TYPE_CATALOG, ENTITY_TYPE_CATALOG_CONTRACT } from '../../../../src/modules/catalog/catalog-entity-types';
import {
  compareVersions,
  findContractBySlugAndVersion,
  findLatestContractBySlug,
  persistCatalogSnapshot,
  upsertCatalog,
  upsertCatalogContract,
} from '../../../../src/modules/catalog/catalog-persistence';

const mockCreateEntity = vi.fn();
const mockPatchAttribute = vi.fn();
const mockFullEntitiesList = vi.fn();

vi.mock('../../../../src/database/middleware', () => ({
  createEntity: (...args: unknown[]) => mockCreateEntity(...args),
  patchAttribute: (...args: unknown[]) => mockPatchAttribute(...args),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({
  fullEntitiesList: (...args: unknown[]) => mockFullEntitiesList(...args),
}));

const mockContext = {} as any;
const mockUser = { id: 'user-1' } as any;

describe('catalog-persistence', () => {
  beforeEach(() => {
    mockCreateEntity.mockReset();
    mockPatchAttribute.mockReset();
    mockFullEntitiesList.mockReset();
  });

  it('upsertCatalog should call createEntity with catalog entity type', async () => {
    mockCreateEntity.mockResolvedValue({ id: 'catalog-1', slug: 'ipinfo' });

    await upsertCatalog(mockContext, mockUser, {
      slug: 'ipinfo',
      title: 'IPinfo',
      description: 'desc',
      use_cases: [],
      verified: true,
      playbook_supported: true,
      manager_supported: true,
      last_synced_at: '2026-07-24T00:00:00.000Z',
      is_deleted: false,
    });

    expect(mockCreateEntity).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      expect.objectContaining({ slug: 'ipinfo' }),
      ENTITY_TYPE_CATALOG,
    );
  });

  it('upsertCatalogContract should demote previous latest when promoting a new one', async () => {
    mockFullEntitiesList.mockResolvedValueOnce([
      { id: 'contract-old', slug: 'ipinfo', version: '1.0.0', is_latest: true },
    ]);
    mockCreateEntity.mockResolvedValue({ id: 'contract-new', slug: 'ipinfo', version: '2.0.0' });

    await upsertCatalogContract(mockContext, mockUser, {
      slug: 'ipinfo',
      version: '2.0.0',
      is_latest: true,
      last_synced_at: '2026-07-24T00:00:00.000Z',
      is_deleted: false,
    });

    expect(mockPatchAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'contract-old',
      ENTITY_TYPE_CATALOG_CONTRACT,
      { is_latest: false },
    );
    expect(mockCreateEntity).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      expect.objectContaining({ slug: 'ipinfo', version: '2.0.0', is_latest: true }),
      ENTITY_TYPE_CATALOG_CONTRACT,
    );
  });

  it('upsertCatalogContract should not lookup latest when incoming contract is not latest', async () => {
    mockCreateEntity.mockResolvedValue({ id: 'contract-1', slug: 'ipinfo', version: '1.0.0' });

    await upsertCatalogContract(mockContext, mockUser, {
      slug: 'ipinfo',
      version: '1.0.0',
      is_latest: false,
      last_synced_at: '2026-07-24T00:00:00.000Z',
      is_deleted: false,
    });

    expect(mockFullEntitiesList).not.toHaveBeenCalled();
    expect(mockPatchAttribute).not.toHaveBeenCalled();
  });

  it('findLatestContractBySlug should filter by slug and is_latest=true', async () => {
    mockFullEntitiesList.mockResolvedValue([{ id: 'contract-2', slug: 'ipinfo', version: '2.0.0' }]);

    const result = await findLatestContractBySlug(mockContext, mockUser, 'ipinfo');

    expect(mockFullEntitiesList).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      [ENTITY_TYPE_CATALOG_CONTRACT],
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['slug'], values: ['ipinfo'] }),
            expect.objectContaining({ key: ['is_latest'], values: [true] }),
          ]),
        }),
      }),
    );
    expect(result?.version).toBe('2.0.0');
  });

  it('findContractBySlugAndVersion should filter by exact slug and version', async () => {
    mockFullEntitiesList.mockResolvedValue([{ id: 'contract-1', slug: 'ipinfo', version: '1.0.0' }]);

    const result = await findContractBySlugAndVersion(mockContext, mockUser, 'ipinfo', '1.0.0');

    expect(mockFullEntitiesList).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      [ENTITY_TYPE_CATALOG_CONTRACT],
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['slug'], values: ['ipinfo'] }),
            expect.objectContaining({ key: ['version'], values: ['1.0.0'] }),
          ]),
        }),
      }),
    );
    expect(result?.id).toBe('contract-1');
  });

  it('compareVersions should correctly order numeric dot-separated versions', () => {
    expect(compareVersions('1.2.10', '1.2.2')).toBeGreaterThan(0);
    expect(compareVersions('2.0.0', '2')).toBe(0);
    expect(compareVersions('1.0.0', '1.0.1')).toBeLessThan(0);
  });

  it('persistCatalogSnapshot should mark latest contract per slug from version ordering', async () => {
    mockFullEntitiesList.mockResolvedValue([]);
    mockCreateEntity.mockResolvedValue({ id: 'entity-id' });

    await persistCatalogSnapshot(mockContext, mockUser, {
      allContracts: [
        {
          slug: 'ipinfo',
          title: 'IPinfo',
          container_version: '1.0.0',
          config_schema: { a: 1 },
          container_image: 'opencti/ipinfo:1.0.0',
        },
        {
          slug: 'ipinfo',
          title: 'IPinfo',
          container_version: '1.2.0',
          config_schema: { a: 2 },
          container_image: 'opencti/ipinfo:1.2.0',
        },
      ],
    });

    const contractCreates = mockCreateEntity.mock.calls.filter((call) => call[3] === ENTITY_TYPE_CATALOG_CONTRACT);
    expect(contractCreates).toHaveLength(2);

    const latestCall = contractCreates.find((call) => call[2].version === '1.2.0');
    const olderCall = contractCreates.find((call) => call[2].version === '1.0.0');

    expect(latestCall?.[2].is_latest).toBe(true);
    expect(olderCall?.[2].is_latest).toBe(false);
  });
});
