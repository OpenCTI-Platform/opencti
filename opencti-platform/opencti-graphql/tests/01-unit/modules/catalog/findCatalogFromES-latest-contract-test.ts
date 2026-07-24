import { beforeEach, describe, expect, it, vi } from 'vitest';
import { findCatalogFromES } from '../../../../src/modules/catalog/catalog-domain';

const findLatestContractsBySlugMock = vi.fn();
const findCatalogLogosByRefsMock = vi.fn();

vi.mock('../../../../src/modules/catalog/catalog-repository', () => ({
  findLatestContractsBySlug: (...args: unknown[]) => findLatestContractsBySlugMock(...args),
  findCatalogLogosByRefs: (...args: unknown[]) => findCatalogLogosByRefsMock(...args),
}));

const mockContext = {} as any;
const mockUser = { id: 'user-1' } as any;

describe('catalog-domain findCatalogFromES', () => {
  beforeEach(() => {
    findLatestContractsBySlugMock.mockReset();
    findCatalogLogosByRefsMock.mockReset();
    findCatalogLogosByRefsMock.mockResolvedValue([]);
  });

  it('should return one entry per latest contract, with contract data as the connector metadata', async () => {
    findLatestContractsBySlugMock.mockResolvedValue([
      {
        id: 'contract-ipinfo-latest',
        slug: 'ipinfo',
        version: '2.1.0',
        entity_type: 'CatalogContract',
        parent_types: ['Internal-Object'],
        standard_id: 'standard-contract-ipinfo',
        title: 'IPinfo',
        description: 'IP enrichment',
        logo_ref: 'logo-hash-ipinfo',
        type: 'INTERNAL_ENRICHMENT',
        config_schema: JSON.stringify({ required: ['IPINFO_TOKEN'] }),
        image: 'opencti/connector-ipinfo:2.1.0',
        support_version: '>=7.2.0',
        max_confidence_level: 80,
      },
      {
        id: 'contract-virustotal-latest',
        slug: 'virustotal',
        version: '2.3.0',
        entity_type: 'CatalogContract',
        parent_types: ['Internal-Object'],
        standard_id: 'standard-contract-virustotal',
        title: 'VirusTotal',
        description: 'File enrichment',
        type: 'EXTERNAL_IMPORT',
        config_schema: '{}',
        image: 'opencti/connector-virustotal:2.3.0',
      },
    ]);
    findCatalogLogosByRefsMock.mockResolvedValue([{ hash: 'logo-hash-ipinfo', data_uri: 'data:image/png;base64,IPINFO' }]);

    const result = await findCatalogFromES(mockContext, mockUser);

    expect(result).toHaveLength(2);
    expect(result.map((c) => c.id)).toEqual(['contract-ipinfo-latest', 'contract-virustotal-latest']);

    const ipinfo = result.find((c) => c.id === 'contract-ipinfo-latest');
    expect(ipinfo?.name).toBe('IPinfo');
    expect(ipinfo?.contracts).toHaveLength(1);

    const parsedContract = JSON.parse(ipinfo?.contracts[0] ?? '{}');
    expect(parsedContract.slug).toBe('ipinfo');
    expect(parsedContract.container_version).toBe('2.1.0');
    expect(parsedContract.container_image).toBe('opencti/connector-ipinfo:2.1.0');
    expect(parsedContract.container_type).toBe('INTERNAL_ENRICHMENT');
    expect(parsedContract.config_schema).toEqual({ required: ['IPINFO_TOKEN'] });
    expect(parsedContract.logo).toBe('data:image/png;base64,IPINFO');
  });

  it('should use fallback defaults when optional contract fields are missing', async () => {
    findLatestContractsBySlugMock.mockResolvedValue([
      {
        id: 'contract-minimal',
        slug: 'minimal',
        version: '1.0.0',
        entity_type: 'CatalogContract',
        parent_types: ['Internal-Object'],
        standard_id: 'standard-contract-minimal',
        title: 'Minimal',
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

  it('should resolve URL logos from logo_ref in ES read path', async () => {
    findLatestContractsBySlugMock.mockResolvedValue([
      {
        id: 'contract-shodan-latest',
        slug: 'shodan',
        version: '1.2.0',
        entity_type: 'CatalogContract',
        parent_types: ['Internal-Object'],
        standard_id: 'standard-contract-shodan',
        title: 'Shodan',
        logo_ref: 'logo-hash-shodan',
        config_schema: '{}',
      },
    ]);
    findCatalogLogosByRefsMock.mockResolvedValue([
      { hash: 'logo-hash-shodan', data_uri: 'https://cdn.example.com/logos/shodan.png' },
    ]);

    const result = await findCatalogFromES(mockContext, mockUser);
    const parsedContract = JSON.parse(result[0].contracts[0]);

    expect(parsedContract.logo).toBe('https://cdn.example.com/logos/shodan.png');
  });

  it('should fallback to legacy inline logo when logo_ref cannot be resolved', async () => {
    findLatestContractsBySlugMock.mockResolvedValue([
      {
        id: 'contract-legacy-logo',
        slug: 'legacy',
        version: '1.0.0',
        entity_type: 'CatalogContract',
        parent_types: ['Internal-Object'],
        standard_id: 'standard-contract-legacy',
        title: 'Legacy',
        logo: 'data:image/png;base64,INLINE',
        logo_ref: 'missing-hash',
        config_schema: '{}',
      },
    ]);
    findCatalogLogosByRefsMock.mockResolvedValue([]);

    const result = await findCatalogFromES(mockContext, mockUser);
    const parsedContract = JSON.parse(result[0].contracts[0]);

    expect(parsedContract.logo).toBe('data:image/png;base64,INLINE');
  });
});
