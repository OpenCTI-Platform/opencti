import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ENTITY_TYPE_CATALOG_CONTRACT, ENTITY_TYPE_CATALOG_LOGO } from '../../../../src/modules/catalog/catalog-entity-types';
import {
  compareVersions,
  findContractBySlugAndVersion,
  findLatestContractBySlug,
  persistCatalogSnapshot,
  upsertCatalogContract,
} from '../../../../src/modules/catalog/catalog-repository';

const mockCreateEntity = vi.fn();
const mockPatchAttribute = vi.fn();
const mockDeleteElementById = vi.fn();
const mockFullEntitiesList = vi.fn();

vi.mock('../../../../src/database/middleware', () => ({
  createEntity: (...args: unknown[]) => mockCreateEntity(...args),
  patchAttribute: (...args: unknown[]) => mockPatchAttribute(...args),
  deleteElementById: (...args: unknown[]) => mockDeleteElementById(...args),
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
    mockDeleteElementById.mockReset();
    mockFullEntitiesList.mockReset();
  });

  it('upsertCatalogContract should call createEntity with contract entity type and all metadata', async () => {
    mockFullEntitiesList.mockResolvedValueOnce([]); // no existing latest for this slug
    mockCreateEntity.mockResolvedValue({ id: 'catalog-1', slug: 'ipinfo', version: '1.0.0' });

    await upsertCatalogContract(mockContext, mockUser, {
      slug: 'ipinfo',
      version: '1.0.0',
      title: 'IPinfo',
      description: 'desc',
      use_cases: [],
      verified: true,
      playbook_supported: true,
      manager_supported: true,
      is_latest: true,
      last_synced_at: '2026-07-24T00:00:00.000Z',
    });

    expect(mockCreateEntity).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      expect.objectContaining({ slug: 'ipinfo', version: '1.0.0', title: 'IPinfo' }),
      ENTITY_TYPE_CATALOG_CONTRACT,
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
      title: 'IPinfo',
      description: '',
      use_cases: [],
      verified: false,
      playbook_supported: false,
      manager_supported: false,
      is_latest: true,
      last_synced_at: '2026-07-24T00:00:00.000Z',
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
      title: 'IPinfo',
      description: '',
      use_cases: [],
      verified: false,
      playbook_supported: false,
      manager_supported: false,
      is_latest: false,
      last_synced_at: '2026-07-24T00:00:00.000Z',
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
    mockFullEntitiesList.mockImplementation((_, __, types, opts) => {
      const isContractType = Array.isArray(types) && types[0] === ENTITY_TYPE_CATALOG_CONTRACT;
      if (!opts && isContractType) return Promise.resolve([]);
      if (!opts && !isContractType) return Promise.resolve([]);
      return Promise.resolve([]);
    });
    mockCreateEntity.mockResolvedValue({ id: 'entity-id' });

    await persistCatalogSnapshot(mockContext, mockUser, {
      allContracts: [
        {
          slug: 'ipinfo',
          title: 'IPinfo',
          version: '1.0.0',
          config_schema: { a: 1 },
          image: 'opencti/ipinfo:1.0.0',
        },
        {
          slug: 'ipinfo',
          title: 'IPinfo',
          version: '1.2.0',
          config_schema: { a: 2 },
          image: 'opencti/ipinfo:1.2.0',
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

  it('persistCatalogSnapshot should hard-delete contracts and catalogs missing from new manifest', async () => {
    mockCreateEntity.mockResolvedValue({ id: 'entity-id' });
    mockDeleteElementById.mockResolvedValue({ id: 'deleted-id' });

    mockFullEntitiesList.mockImplementation((_, __, types, opts) => {
      const isContractType = Array.isArray(types) && types[0] === ENTITY_TYPE_CATALOG_CONTRACT;

      if (!opts && isContractType) {
        return Promise.resolve([
          { id: 'contract-ipinfo-1.0.0', slug: 'ipinfo', version: '1.0.0' },
          { id: 'contract-shodan-1.1.0', slug: 'shodan', version: '1.1.0' },
        ]);
      }

      return Promise.resolve([]);
    });

    await persistCatalogSnapshot(mockContext, mockUser, {
      allContracts: [
        {
          slug: 'ipinfo',
          title: 'IPinfo',
          version: '1.0.0',
          config_schema: { a: 1 },
          image: 'opencti/ipinfo:1.0.0',
        },
      ],
    });

    expect(mockDeleteElementById).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'contract-shodan-1.1.0',
      ENTITY_TYPE_CATALOG_CONTRACT,
    );

    expect(mockDeleteElementById).not.toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'contract-ipinfo-1.0.0',
      ENTITY_TYPE_CATALOG_CONTRACT,
    );
  });

  it('persistCatalogSnapshot should store logo once and reference it from each version', async () => {
    mockFullEntitiesList.mockResolvedValue([]);
    mockCreateEntity.mockResolvedValue({ id: 'entity-id' });

    await persistCatalogSnapshot(mockContext, mockUser, {
      allContracts: [
        {
          slug: 'ipinfo',
          title: 'IPinfo',
          version: '1.0.0',
          logo: 'data:image/png;base64,AAA',
          config_schema: {},
        },
        {
          slug: 'ipinfo',
          title: 'IPinfo',
          version: '1.1.0',
          logo: 'data:image/png;base64,AAA',
          config_schema: {},
        },
      ],
    });

    const logoCreates = mockCreateEntity.mock.calls.filter((call) => call[3] === ENTITY_TYPE_CATALOG_LOGO);
    const contractCreates = mockCreateEntity.mock.calls.filter((call) => call[3] === ENTITY_TYPE_CATALOG_CONTRACT);

    expect(logoCreates).toHaveLength(1);
    expect(contractCreates).toHaveLength(2);
    expect(contractCreates[0][2]).toEqual(expect.objectContaining({ logo_ref: expect.any(String) }));
    expect(contractCreates[1][2]).toEqual(expect.objectContaining({ logo_ref: expect.any(String) }));
    expect(contractCreates[0][2].logo_ref).toBe(contractCreates[1][2].logo_ref);
  });

  it('persistCatalogSnapshot should support URL logos and deduplicate identical URLs', async () => {
    mockFullEntitiesList.mockResolvedValue([]);
    mockCreateEntity.mockResolvedValue({ id: 'entity-id' });

    await persistCatalogSnapshot(mockContext, mockUser, {
      allContracts: [
        {
          slug: 'shodan',
          title: 'Shodan',
          version: '1.1.0',
          logo: 'https://cdn.example.com/logos/shodan.png',
          config_schema: {},
        },
        {
          slug: 'shodan',
          title: 'Shodan',
          version: '1.2.0',
          logo: 'https://cdn.example.com/logos/shodan.png',
          config_schema: {},
        },
      ],
    });

    const logoCreates = mockCreateEntity.mock.calls.filter((call) => call[3] === ENTITY_TYPE_CATALOG_LOGO);
    const contractCreates = mockCreateEntity.mock.calls.filter((call) => call[3] === ENTITY_TYPE_CATALOG_CONTRACT);

    expect(logoCreates).toHaveLength(1);
    expect(contractCreates).toHaveLength(2);
    expect(contractCreates[0][2]).toEqual(expect.objectContaining({ logo_ref: expect.any(String) }));
    expect(contractCreates[1][2]).toEqual(expect.objectContaining({ logo_ref: expect.any(String) }));
    expect(contractCreates[0][2].logo_ref).toBe(contractCreates[1][2].logo_ref);
  });

  it('persistCatalogSnapshot should delete orphan logos no longer referenced by contracts', async () => {
    mockCreateEntity.mockResolvedValue({ id: 'entity-id' });
    mockDeleteElementById.mockResolvedValue({ id: 'deleted-id' });

    let contractListCallCount = 0;

    mockFullEntitiesList.mockImplementation((_, __, types, opts) => {
      const isContractType = Array.isArray(types) && types[0] === ENTITY_TYPE_CATALOG_CONTRACT;
      const isLogoType = Array.isArray(types) && types[0] === ENTITY_TYPE_CATALOG_LOGO;

      if (!opts && isContractType) {
        contractListCallCount += 1;
        if (contractListCallCount === 1) {
          // Existing contracts before sync.
          return Promise.resolve([
            { id: 'contract-ipinfo-1.0.0', slug: 'ipinfo', version: '1.0.0', logo_ref: 'hash-ipinfo' },
            { id: 'contract-shodan-1.1.0', slug: 'shodan', version: '1.1.0', logo_ref: 'hash-shodan' },
          ]);
        }
        // Contracts after sync (only ipinfo remains).
        return Promise.resolve([
          { id: 'contract-ipinfo-1.0.0', slug: 'ipinfo', version: '1.0.0', logo_ref: 'hash-ipinfo' },
        ]);
      }

      if (!opts && isLogoType) {
        return Promise.resolve([
          { id: 'logo-ipinfo', hash: 'hash-ipinfo', data_uri: 'data:image/png;base64,AAA' },
          { id: 'logo-shodan', hash: 'hash-shodan', data_uri: 'data:image/png;base64,BBB' },
        ]);
      }

      return Promise.resolve([]);
    });

    await persistCatalogSnapshot(mockContext, mockUser, {
      allContracts: [
        {
          slug: 'ipinfo',
          title: 'IPinfo',
          version: '1.0.0',
          logo: 'data:image/png;base64,AAA',
          config_schema: {},
        },
      ],
    });

    expect(mockDeleteElementById).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'contract-shodan-1.1.0',
      ENTITY_TYPE_CATALOG_CONTRACT,
    );
    expect(mockDeleteElementById).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'logo-shodan',
      ENTITY_TYPE_CATALOG_LOGO,
    );
    expect(mockDeleteElementById).not.toHaveBeenCalledWith(
      mockContext,
      mockUser,
      'logo-ipinfo',
      ENTITY_TYPE_CATALOG_LOGO,
    );
  });
});
