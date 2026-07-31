import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ENTITY_TYPE_CATALOG_CONTRACT, ENTITY_TYPE_CATALOG_LOGO, ENTITY_TYPE_CATALOG_MANIFEST } from '../../../../src/modules/catalog/catalog-entity-types';
import {
  compareVersions,
  findCatalogLogoByRef,
  findContractFromESByContainerImage,
  findContractFromESBySlug,
  findCatalogManifestBySourceUri,
  findContractBySlugAndVersion,
  findLatestContractByContainerImage,
  findLatestContractBySlug,
  persistCatalogSnapshot,
  upsertCatalogManifest,
  upsertCatalogContract,
} from '../../../../src/modules/catalog/catalog-repository';

const mockCreateEntity = vi.fn();
const mockDeleteElementById = vi.fn();
const mockFullEntitiesList = vi.fn();

vi.mock('../../../../src/database/middleware', () => ({
  createEntity: (...args: unknown[]) => mockCreateEntity(...args),
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
    mockDeleteElementById.mockReset();
    mockFullEntitiesList.mockReset();
  });

  it('upsertCatalogContract should call createEntity with contract entity type and all metadata', async () => {
    mockCreateEntity.mockResolvedValue({ id: 'catalog-1', slug: 'ipinfo', version: '1.0.0' });

    await upsertCatalogContract(mockContext, mockUser, {
      catalog_id: 'filigran-catalog-id',
      slug: 'ipinfo',
      version: '1.0.0',
      title: 'IPinfo',
      description: 'desc',
      use_cases: [],
      verified: true,
      playbook_supported: true,
      manager_supported: true,
      last_synced_at: '2026-07-24T00:00:00.000Z',
    });

    expect(mockCreateEntity).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      expect.objectContaining({ slug: 'ipinfo', version: '1.0.0', title: 'IPinfo' }),
      ENTITY_TYPE_CATALOG_CONTRACT,
    );
  });

  it('upsertCatalogContract should not lookup latest contracts', async () => {
    mockCreateEntity.mockResolvedValue({ id: 'contract-1', slug: 'ipinfo', version: '1.0.0' });

    await upsertCatalogContract(mockContext, mockUser, {
      catalog_id: 'filigran-catalog-id',
      slug: 'ipinfo',
      version: '1.0.0',
      title: 'IPinfo',
      description: '',
      use_cases: [],
      verified: false,
      playbook_supported: false,
      manager_supported: false,
      last_synced_at: '2026-07-24T00:00:00.000Z',
    });

    expect(mockFullEntitiesList).not.toHaveBeenCalled();
  });

  it('findLatestContractBySlug should filter by slug and return highest version', async () => {
    mockFullEntitiesList.mockResolvedValue([
      { id: 'contract-1', slug: 'ipinfo', version: '2025.04.2' },
      { id: 'contract-2', slug: 'ipinfo', version: '2025.10.1' },
      { id: 'contract-3', slug: 'ipinfo', version: '2025.09.9' },
    ]);

    const result = await findLatestContractBySlug(mockContext, mockUser, 'ipinfo');

    expect(mockFullEntitiesList).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      [ENTITY_TYPE_CATALOG_CONTRACT],
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['slug'], values: ['ipinfo'] }),
          ]),
        }),
      }),
    );
    expect(result?.version).toBe('2025.10.1');
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

  it('findLatestContractByContainerImage should filter by image and return highest version', async () => {
    mockFullEntitiesList.mockResolvedValue([
      { id: 'contract-1', slug: 'ipinfo', version: '2025.04.2', image: 'opencti/ipinfo' },
      { id: 'contract-2', slug: 'ipinfo', version: '2025.10.1', image: 'opencti/ipinfo' },
      { id: 'contract-3', slug: 'ipinfo', version: '2025.09.9', image: 'opencti/ipinfo' },
    ]);

    const result = await findLatestContractByContainerImage(mockContext, mockUser, 'opencti/ipinfo');

    expect(mockFullEntitiesList).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      [ENTITY_TYPE_CATALOG_CONTRACT],
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['image'], values: ['opencti/ipinfo'] }),
          ]),
        }),
      }),
    );
    expect(result?.version).toBe('2025.10.1');
  });

  it('findCatalogLogoByRef should filter by hash and return first logo', async () => {
    mockFullEntitiesList.mockResolvedValue([{ id: 'logo-1', hash: 'hash-ipinfo', data_uri: 'data:image/png;base64,AAA' }]);

    const result = await findCatalogLogoByRef(mockContext, mockUser, 'hash-ipinfo');

    expect(mockFullEntitiesList).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      [ENTITY_TYPE_CATALOG_LOGO],
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['hash'], values: ['hash-ipinfo'] }),
          ]),
        }),
      }),
    );
    expect(result?.id).toBe('logo-1');
  });

  it('findContractFromESBySlug should return catalog_id and serialized contract', async () => {
    mockFullEntitiesList
      .mockResolvedValueOnce([
        {
          id: 'contract-1',
          catalog_id: 'catalog-1',
          slug: 'ipinfo',
          version: '2025.10.1',
          title: 'IPinfo',
          description: 'desc',
          short_description: 'short',
          use_cases: ['enrichment'],
          verified: true,
          playbook_supported: false,
          manager_supported: true,
          source_code: 'https://example.com',
          subscription_link: 'https://example.com/sub',
          type: 'INTERNAL_ENRICHMENT',
          image: 'opencti/ipinfo',
          config_schema: JSON.stringify({ type: 'object', properties: {}, required: [] }),
          logo_ref: 'hash-ipinfo',
        },
      ])
      .mockResolvedValueOnce([
        { id: 'logo-1', hash: 'hash-ipinfo', data_uri: 'data:image/png;base64,AAA' },
      ]);

    const result = await findContractFromESBySlug(mockContext, mockUser, 'ipinfo');

    expect(result).toBeDefined();
    expect(result?.catalog_id).toBe('catalog-1');
    const parsedContract = JSON.parse(result!.contract);
    expect(parsedContract.slug).toBe('ipinfo');
    expect(parsedContract.logo).toBe('data:image/png;base64,AAA');
  });

  it('findContractFromESByContainerImage should return latest contract for image', async () => {
    mockFullEntitiesList
      .mockResolvedValueOnce([
        {
          id: 'contract-1',
          catalog_id: 'catalog-1',
          slug: 'ipinfo',
          version: '2025.10.1',
          title: 'IPinfo',
          description: 'desc',
          short_description: 'short',
          use_cases: ['enrichment'],
          verified: true,
          playbook_supported: false,
          manager_supported: true,
          type: 'INTERNAL_ENRICHMENT',
          image: 'opencti/ipinfo',
          config_schema: JSON.stringify({ type: 'object', properties: {}, required: [] }),
        },
        {
          id: 'contract-2',
          catalog_id: 'catalog-1',
          slug: 'ipinfo',
          version: '2025.09.9',
          title: 'IPinfo old',
          description: 'desc old',
          short_description: 'short old',
          use_cases: ['enrichment'],
          verified: true,
          playbook_supported: false,
          manager_supported: true,
          type: 'INTERNAL_ENRICHMENT',
          image: 'opencti/ipinfo',
          config_schema: JSON.stringify({ type: 'object', properties: {}, required: [] }),
        },
      ]);

    const result = await findContractFromESByContainerImage(mockContext, mockUser, 'opencti/ipinfo');

    expect(result).toBeDefined();
    const parsedContract = JSON.parse(result!.contract);
    expect(parsedContract.container_version).toBe('2025.10.1');
    expect(parsedContract.container_image).toBe('opencti/ipinfo');
  });

  it('compareVersions should correctly order numeric dot-separated versions', () => {
    expect(compareVersions('1.2.10', '1.2.2')).toBeGreaterThan(0);
    expect(compareVersions('2.0.0', '2')).toBe(0);
    expect(compareVersions('1.0.0', '1.0.1')).toBeLessThan(0);
  });

  it('persistCatalogSnapshot should persist all versions without is_latest', async () => {
    mockFullEntitiesList.mockImplementation((_, __, types, opts) => {
      const isContractType = Array.isArray(types) && types[0] === ENTITY_TYPE_CATALOG_CONTRACT;
      if (!opts && isContractType) return Promise.resolve([]);
      if (!opts && !isContractType) return Promise.resolve([]);
      return Promise.resolve([]);
    });
    mockCreateEntity.mockResolvedValue({ id: 'entity-id' });

    await persistCatalogSnapshot(mockContext, mockUser, {
      catalogId: 'filigran-catalog-id',
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

    expect(latestCall?.[2]).not.toHaveProperty('is_latest');
    expect(olderCall?.[2]).not.toHaveProperty('is_latest');
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
      catalogId: 'filigran-catalog-id',
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
      catalogId: 'filigran-catalog-id',
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
      catalogId: 'filigran-catalog-id',
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

  it('upsertCatalogManifest should persist metadata with CatalogManifest entity type', async () => {
    mockCreateEntity.mockResolvedValue({ id: 'manifest-1', source_uri: 'https://hub.example/catalog' });

    await upsertCatalogManifest(mockContext, mockUser, {
      source_uri: 'https://hub.example/catalog',
      catalog_id: 'filigran-catalog-id',
      revision: 'etag-123',
      manifest_version: 'connector-manifest-7.260728.0-260729083711',
      version: '7.260728.0',
    });

    expect(mockCreateEntity).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      expect.objectContaining({
        source_uri: 'https://hub.example/catalog',
        catalog_id: 'filigran-catalog-id',
        revision: 'etag-123',
      }),
      ENTITY_TYPE_CATALOG_MANIFEST,
    );
  });

  it('findCatalogManifestBySourceUri should load metadata by source uri', async () => {
    mockFullEntitiesList.mockResolvedValue([{ id: 'manifest-1', source_uri: 'https://hub.example/catalog', revision: 'etag-123' }]);

    const result = await findCatalogManifestBySourceUri(mockContext, mockUser, 'https://hub.example/catalog');

    expect(mockFullEntitiesList).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      [ENTITY_TYPE_CATALOG_MANIFEST],
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['source_uri'], values: ['https://hub.example/catalog'] }),
          ]),
        }),
      }),
    );
    expect(result?.id).toBe('manifest-1');
  });

  it('findCatalogManifestBySourceUri should preserve quoted persisted etag revision as-is', async () => {
    mockFullEntitiesList.mockResolvedValue([{ id: 'manifest-2', source_uri: 'https://hub.example/catalog', revision: '"connector-manifest-7.260728.0-260729083711"' }]);

    const result = await findCatalogManifestBySourceUri(mockContext, mockUser, 'https://hub.example/catalog');

    expect(result?.revision).toBe('"connector-manifest-7.260728.0-260729083711"');
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
      catalogId: 'filigran-catalog-id',
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
