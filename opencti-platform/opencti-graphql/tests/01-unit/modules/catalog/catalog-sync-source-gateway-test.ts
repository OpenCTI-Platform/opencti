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
import { buildErrorScope } from '../../../../src/config/error-origin';

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
  min_version: '6.7.0',
  max_version: '7.5.0',
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

  it('should preserve support_version range and id from V0 contract DTO', () => {
    const mapped = mapCatalogContractDtoToCatalogContractSyncSource(baseV0Contract as any);
    expect(mapped.id).toBe('ipinfo-1.2.3');
    expect(mapped.support_version).toBe('>= 6.7.0');
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
    expect(source.contracts[0].support_version).toBe('>= 6.7.0');
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
    expect(source.contracts[0].support_version).toBeNull();
    expect(source.contracts[0].min_version).toBe('6.7.0');
    expect(source.contracts[0].max_version).toBe('7.5.0');
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

  describe('remote source error classification (RFC 0006)', () => {
    const remoteSource = { kind: 'remote', uri: 'https://catalog.example/manifest.json' } as const;
    const axiosFailure = (fields: Record<string, unknown>) => Object.assign(new Error('Request failed'), fields);
    const fetchError = (failure: unknown) => {
      mockGet.mockRejectedValue(failure);
      return fetchSourceCatalog(remoteSource).catch((e: unknown) => e);
    };

    it('should classify an unreachable source as infra', async () => {
      const error = await fetchError(axiosFailure({ code: 'ECONNREFUSED' }));
      expect(buildErrorScope(error)).toEqual({ origin: 'infra', dependency: 'remote_http' });
    });

    it('should classify a timed out request as infra', async () => {
      const error = await fetchError(axiosFailure({ code: 'ERR_CANCELED' }));
      expect(buildErrorScope(error).origin).toBe('infra');
    });

    it('should classify a failing or throttling source as infra', async () => {
      expect(buildErrorScope(await fetchError(axiosFailure({ response: { status: 502 } }))).origin).toBe('infra');
      expect(buildErrorScope(await fetchError(axiosFailure({ response: { status: 429 } }))).origin).toBe('infra');
    });

    it('should leave a rejected request untouched', async () => {
      const failure = axiosFailure({ response: { status: 404 } });
      expect(await fetchError(failure)).toBe(failure);
    });

    it('should classify the revision hint request the same way', async () => {
      mockHead.mockRejectedValue(axiosFailure({ code: 'ETIMEDOUT' }));
      const error = await fetchSourceCatalogRevisionHint(remoteSource).catch((e: unknown) => e);
      expect(buildErrorScope(error)).toEqual({ origin: 'infra', dependency: 'remote_http' });
    });

    it('should classify a manifest that is not valid JSON as input', async () => {
      mockGet.mockResolvedValue({ data: '<html>maintenance</html>' });
      const error = await fetchSourceCatalog(remoteSource).catch((e: unknown) => e);
      expect(buildErrorScope(error).origin).toBe('input');
    });
  });
});
