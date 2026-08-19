import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockReadFile, mockGet, mockHead, mockGetOrCompileValidator } = vi.hoisted(() => ({
  mockReadFile: vi.fn(),
  mockGet: vi.fn(),
  mockHead: vi.fn(),
  mockGetOrCompileValidator: vi.fn(),
}));

vi.mock('node:fs/promises', () => ({
  readFile: mockReadFile,
}));

vi.mock('../../../../src/config/conf', () => ({
  default: {
    get: vi.fn(() => undefined),
  },
  logApp: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
  TEST_MODE: true,
  ENABLED_METRICS: false,
  booleanConf: vi.fn(() => false),
  loadCert: vi.fn(() => ''),
}));

vi.mock('../../../../src/database/utils', () => ({
  isEmptyField: (value: unknown) => value === null || value === undefined || value === '',
}));

vi.mock('../../../../src/modules/catalog/catalog-domain', () => ({
  getOrCompileValidator: mockGetOrCompileValidator,
}));

vi.mock('../../../../src/utils/http-client', () => ({
  getHttpClient: vi.fn(() => ({
    get: mockGet,
    head: mockHead,
  })),
}));

vi.mock('../../../../src/modules/catalog/catalog-logger', () => ({
  logCatalog: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

import {
  fetchSourceCatalog,
  fetchSourceCatalogRevisionHint,
  mapCatalogContractDtoToCatalogContractSyncSource,
} from '../../../../src/modules/catalog/sync/catalog-sync-source-gateway';

const baseV0Contract = {
  title: 'IPinfo',
  slug: 'ipinfo',
  description: 'desc',
  short_description: 'short',
  logo: 'data:image/png;base64,Zm9v',
  use_cases: [],
  verified: true,
  last_verified_date: '2024-01-01',
  playbook_supported: false,
  max_confidence_level: 50,
  support_version: '>= 6.7.0',
  subscription_link: null,
  source_code: '',
  manager_supported: true,
  container_version: '1.2.3',
  container_image: 'opencti/connector-ipinfo',
  container_type: 'EXTERNAL_IMPORT',
  config_schema: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'id',
    type: 'object',
    properties: {},
    required: [],
    additionalProperties: true,
  },
  license_type: null,
  solution_categories: [],
  contact: null,
};

const baseV1Contract = {
  id: 'ipinfo-1.2.3',
  title: 'IPinfo',
  slug: 'ipinfo',
  description: 'desc',
  short_description: 'short',
  logo: 'data:image/png;base64,Zm9v',
  use_cases: [],
  verified: true,
  last_verified_date: '2024-01-01',
  subscription_link: null,
  source_code: '',
  manager_supported: true,
  support_version: '6.7.0',
  license_type: null,
  contact: null,
  solution_categories: [],
  version: '1.2.3',
  image_name: 'opencti/connector-ipinfo',
  image_type: 'EXTERNAL_IMPORT',
  additional_properties: {
    playbook_supported: true,
    max_confidence_level: 80,
  },
  config_schema: {
    type: 'object',
    properties: {},
    required: [],
    additionalProperties: true,
  },
};

describe('catalog-sync-source-gateway', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetOrCompileValidator.mockReturnValue({});
  });

  it('should normalize support_version and id from V0 contract DTO', () => {
    const mapped = mapCatalogContractDtoToCatalogContractSyncSource(baseV0Contract as any);
    expect(mapped.id).toBe('ipinfo-1.2.3');
    expect(mapped.support_version).toBe('6.7.0');
  });

  it('should map V0 catalog sources', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      id: 'filigran',
      name: 'Filigran catalog',
      description: 'catalog',
      version: '6.8.0',
      contracts: [baseV0Contract],
    }));
    const source = await fetchSourceCatalog({
      kind: 'local',
      filepath: '/tmp/catalog.json',
      uri: 'file:///tmp/catalog.json',
    });
    expect(source.manifest_schema_version).toBe('0');
    expect(source.manifest_version).toBeNull();
    expect(source.product_version).toBe('6.8.0');
    expect(source.contracts).toHaveLength(1);
    expect(source.contracts[0].support_version).toBe('6.7.0');
  });

  it('should map V1 catalog sources', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      id: 'filigran',
      name: 'Filigran catalog',
      description: 'catalog',
      manifest_schema_version: '1',
      manifest_version: '2026.08',
      product_version: '6.8.0',
      contracts: [baseV1Contract],
    }));
    const source = await fetchSourceCatalog({
      kind: 'local',
      filepath: '/tmp/catalog-v1.json',
      uri: 'file:///tmp/catalog-v1.json',
    });
    expect(source.manifest_schema_version).toBe('1');
    expect(source.manifest_version).toBe('2026.08');
    expect(source.product_version).toBe('6.8.0');
    expect(source.contracts[0].id).toBe('ipinfo-1.2.3');
    expect(source.contracts[0].container_image).toBe('opencti/connector-ipinfo');
  });

  it('should reject unsupported schema versions', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      id: 'filigran',
      name: 'Filigran catalog',
      description: 'catalog',
      manifest_schema_version: '2',
      contracts: [],
    }));
    await expect(fetchSourceCatalog({
      kind: 'local',
      filepath: '/tmp/catalog-invalid.json',
      uri: 'file:///tmp/catalog-invalid.json',
    })).rejects.toThrowError('Unsupported catalog schema version');
  });

  it('should reject unrecognized formats', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({ hello: 'world' }));
    await expect(fetchSourceCatalog({
      kind: 'local',
      filepath: '/tmp/catalog-invalid.json',
      uri: 'file:///tmp/catalog-invalid.json',
    })).rejects.toThrowError('Unrecognized catalog format');
  });

  it('should reject manager-supported contracts missing container image', async () => {
    const invalidContract = { ...baseV0Contract, container_image: '' };
    mockReadFile.mockResolvedValue(JSON.stringify({
      id: 'filigran',
      name: 'Filigran catalog',
      description: 'catalog',
      version: '6.8.0',
      contracts: [invalidContract],
    }));
    await expect(fetchSourceCatalog({
      kind: 'local',
      filepath: '/tmp/catalog-invalid-contract.json',
      uri: 'file:///tmp/catalog-invalid-contract.json',
    })).rejects.toThrowError('Contract must define container_image field');
  });

  it('should return revision hint from remote ETag header', async () => {
    mockHead.mockResolvedValue({ headers: { etag: '"abc123"' } });
    const hint = await fetchSourceCatalogRevisionHint({
      kind: 'remote',
      uri: 'https://catalog.example.org/manifest.json',
    });
    expect(hint).toBe('"abc123"');
  });

  it('should return undefined revision hint when ETag is missing', async () => {
    mockHead.mockResolvedValue({ headers: {} });
    const hint = await fetchSourceCatalogRevisionHint({
      kind: 'remote',
      uri: 'https://catalog.example.org/manifest.json',
    });
    expect(hint).toBeUndefined();
  });
});
