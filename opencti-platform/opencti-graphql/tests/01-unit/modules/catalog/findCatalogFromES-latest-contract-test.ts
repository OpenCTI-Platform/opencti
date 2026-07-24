import { beforeEach, describe, expect, it, vi } from 'vitest';
import { findCatalogFromES } from '../../../../src/modules/catalog/catalog-domain';

const findLatestContractsBySlugMock = vi.fn();

vi.mock('../../../../src/modules/catalog/catalog-repository', () => ({
  findLatestContractsBySlug: (...args: unknown[]) => findLatestContractsBySlugMock(...args),
}));

const mockContext = {} as any;
const mockUser = { id: 'user-1' } as any;

describe('catalog-domain findCatalogFromES', () => {
  beforeEach(() => {
    findLatestContractsBySlugMock.mockReset();
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
});
