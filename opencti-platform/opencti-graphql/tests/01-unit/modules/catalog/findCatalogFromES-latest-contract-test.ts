import { beforeEach, describe, expect, it, vi } from 'vitest';
import { findCatalogFromES } from '../../../../src/modules/catalog/catalog-domain';

const findAllCatalogsMock = vi.fn();
const findLatestContractsBySlugMock = vi.fn();

vi.mock('../../../../src/modules/catalog/catalog-persistence', () => ({
  findAllCatalogs: (...args: unknown[]) => findAllCatalogsMock(...args),
  findLatestContractsBySlug: (...args: unknown[]) => findLatestContractsBySlugMock(...args),
}));

const mockContext = {} as any;
const mockUser = { id: 'user-1' } as any;

describe('catalog-domain findCatalogFromES', () => {
  beforeEach(() => {
    findAllCatalogsMock.mockReset();
    findLatestContractsBySlugMock.mockReset();
  });

  it('should return only non-deleted catalogs and attach the latest contract by slug', async () => {
    findAllCatalogsMock.mockResolvedValue([
      {
        id: 'catalog-ipinfo',
        entity_type: 'Catalog',
        parent_types: ['Internal-Object'],
        standard_id: 'standard-catalog-ipinfo',
        slug: 'ipinfo',
        title: 'IPinfo',
        description: 'IP enrichment',
        is_deleted: false,
        type: 'INTERNAL_ENRICHMENT',
      },
      {
        id: 'catalog-deleted',
        entity_type: 'Catalog',
        parent_types: ['Internal-Object'],
        standard_id: 'standard-catalog-deleted',
        slug: 'deleted',
        title: 'Deleted',
        description: 'Should not be returned',
        is_deleted: true,
      },
      {
        id: 'catalog-nocontract',
        entity_type: 'Catalog',
        parent_types: ['Internal-Object'],
        standard_id: 'standard-catalog-nocontract',
        slug: 'nocontract',
        title: 'No Contract',
        description: 'No latest contract found',
        is_deleted: false,
      },
    ]);

    findLatestContractsBySlugMock.mockResolvedValue([
      {
        id: 'contract-ipinfo-latest',
        slug: 'ipinfo',
        version: '2.1.0',
        config_schema: JSON.stringify({ required: ['IPINFO_TOKEN'] }),
        container_image: 'opencti/connector-ipinfo:2.1.0',
        class_name: 'IPInfoConnector',
        support_version: '>=7.2.0',
        max_confidence_level: 80,
      },
      {
        id: 'contract-orphan',
        slug: 'orphan',
        version: '9.9.9',
        config_schema: '{}',
      },
    ]);

    const result = await findCatalogFromES(mockContext, mockUser);

    expect(result).toHaveLength(2);
    expect(result.map((c) => c.id)).toEqual(['catalog-ipinfo', 'catalog-nocontract']);

    const ipinfo = result.find((c) => c.id === 'catalog-ipinfo');
    expect(ipinfo?.contracts).toHaveLength(1);

    const parsedContract = JSON.parse(ipinfo?.contracts[0] ?? '{}');
    expect(parsedContract.slug).toBe('ipinfo');
    expect(parsedContract.container_version).toBe('2.1.0');
    expect(parsedContract.container_image).toBe('opencti/connector-ipinfo:2.1.0');
    expect(parsedContract.container_type).toBe('INTERNAL_ENRICHMENT');
    expect(parsedContract.config_schema).toEqual({ required: ['IPINFO_TOKEN'] });

    const noContract = result.find((c) => c.id === 'catalog-nocontract');
    expect(noContract?.contracts).toEqual([]);
  });

  it('should use fallback defaults when optional catalog and contract fields are missing', async () => {
    findAllCatalogsMock.mockResolvedValue([
      {
        id: 'catalog-minimal',
        entity_type: 'Catalog',
        parent_types: ['Internal-Object'],
        standard_id: 'standard-catalog-minimal',
        slug: 'minimal',
        title: 'Minimal',
        is_deleted: false,
      },
    ]);

    findLatestContractsBySlugMock.mockResolvedValue([
      {
        slug: 'minimal',
        version: '1.0.0',
        config_schema: '{}',
      },
    ]);

    const result = await findCatalogFromES(mockContext, mockUser);
    const parsedContract = JSON.parse(result[0].contracts[0]);

    expect(parsedContract.description).toBe('');
    expect(parsedContract.short_description).toBe('');
    expect(parsedContract.container_type).toBe('EXTERNAL_IMPORT');
    expect(parsedContract.max_confidence_level).toBe(100);
  });
});
