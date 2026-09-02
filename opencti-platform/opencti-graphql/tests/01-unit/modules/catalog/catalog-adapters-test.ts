import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const confGetMock = vi.fn();
const readFileMock = vi.fn();

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: (...args: unknown[]) => confGetMock(...args),
    },
    TEST_MODE: false,
    isFeatureEnabled: () => false,
    logApp: {
      ...actual.logApp,
      warn: vi.fn(),
      info: vi.fn(),
      debug: vi.fn(),
    },
    PLATFORM_VERSION: '7.260722.0',
  };
});

vi.mock('node:fs/promises', () => ({
  readFile: (...args: unknown[]) => readFileMock(...args),
}));

vi.mock('../../../../src/__generated__/opencti-manifest.json', () => ({
  default: {
    id: 'embedded-catalog',
    name: 'Embedded Catalog',
    description: 'Embedded test catalog',
    contracts: [],
  },
}));

describe('catalog-adapters', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    confGetMock.mockImplementation((key: string) => {
      if (key === 'xtm:xtmhub_url') return 'https://hub.filigran.io/';
      if (key === 'app:custom_catalogs') return [];
      return undefined;
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('resolveCatalogSource builds default remote URL from hub config', async () => {
    const { resolveCatalogSource } = await import('../../../../src/modules/catalog/catalog-adapters');

    const result = resolveCatalogSource(undefined);

    expect(result).toEqual({
      source: {
        kind: 'remote',
        uri: 'https://hub.filigran.io/opencti/7.260722.0/connector/manifests/latest',
      },
      originalUri: 'https://hub.filigran.io/opencti/7.260722.0/connector/manifests/latest',
    });
  });

  it('resolveCatalogSource returns provided http URI as remote source', async () => {
    const { resolveCatalogSource } = await import('../../../../src/modules/catalog/catalog-adapters');

    const result = resolveCatalogSource('https://custom.example/catalog');

    expect(result).toEqual({
      source: { kind: 'remote', uri: 'https://custom.example/catalog' },
      originalUri: 'https://custom.example/catalog',
    });
  });

  it('resolveCatalogSource resolves relative file paths to absolute local paths', async () => {
    const { resolveCatalogSource } = await import('../../../../src/modules/catalog/catalog-adapters');

    const result = resolveCatalogSource('fixtures/catalog.json');

    expect(result.source.kind).toBe('local');
    expect(result.source.uri).toBe(path.resolve(process.cwd(), 'fixtures/catalog.json'));
    expect(result.originalUri).toBe('fixtures/catalog.json');
  });

  it('resolveCatalogSource strips file:// prefix', async () => {
    const { resolveCatalogSource } = await import('../../../../src/modules/catalog/catalog-adapters');

    const result = resolveCatalogSource('file:///tmp/test-catalog.json');

    expect(result).toEqual({
      source: { kind: 'local', uri: '/tmp/test-catalog.json' },
      originalUri: 'file:///tmp/test-catalog.json',
    });
  });

  it('resolveCatalogSource throws on unsupported URI schemes', async () => {
    const { resolveCatalogSource } = await import('../../../../src/modules/catalog/catalog-adapters');

    expect(() => resolveCatalogSource('ftp://catalog.json')).toThrow('Unsupported catalog source URI scheme: ftp://catalog.json');
  });

  it('NewManifestAdapter.fetch reads and parses local JSON manifest', async () => {
    readFileMock.mockResolvedValue('{"id":"manifest-1","contracts":[]}');
    const { NewManifestAdapter } = await import('../../../../src/modules/catalog/catalog-adapters');
    const adapter = new NewManifestAdapter();

    const result = await adapter.fetch({ kind: 'local', uri: '/tmp/manifest.json' });

    expect(readFileMock).toHaveBeenCalledWith('/tmp/manifest.json', { encoding: 'utf8', flag: 'r' });
    expect(result).toEqual({ id: 'manifest-1', contracts: [] });
  });

  it('NewManifestAdapter.fetch returns remote JSON when response is ok', async () => {
    const remoteManifest = { id: 'remote-1', contracts: [] };
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => remoteManifest });
    vi.stubGlobal('fetch', fetchMock);

    const { NewManifestAdapter } = await import('../../../../src/modules/catalog/catalog-adapters');
    const adapter = new NewManifestAdapter();

    const result = await adapter.fetch({ kind: 'remote', uri: 'https://hub/catalog' }, { signal: undefined });

    expect(fetchMock).toHaveBeenCalledWith('https://hub/catalog', { signal: undefined });
    expect(result).toEqual(remoteManifest);
  });

  it('NewManifestAdapter.fetch throws on non-ok remote response', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 503 });
    vi.stubGlobal('fetch', fetchMock);

    const { NewManifestAdapter } = await import('../../../../src/modules/catalog/catalog-adapters');
    const adapter = new NewManifestAdapter();

    await expect(adapter.fetch({ kind: 'remote', uri: 'https://hub/catalog' })).rejects.toThrow(
      'Failed to fetch remote catalog (503) from https://hub/catalog',
    );
  });

  it('NewManifestAdapter.toPersistableContracts validates required manifest fields', async () => {
    const { NewManifestAdapter } = await import('../../../../src/modules/catalog/catalog-adapters');
    const adapter = new NewManifestAdapter();

    expect(() => adapter.toPersistableContracts({ contracts: [] })).toThrow('Catalog manifest is missing required fields: id and contracts');
    expect(() => adapter.toPersistableContracts({ id: 'catalog-1', contracts: 'not-array' })).toThrow('Catalog manifest is missing required fields: id and contracts');
  });

  it('NewManifestAdapter.toPersistableContracts enforces manager-supported required fields', async () => {
    const { NewManifestAdapter } = await import('../../../../src/modules/catalog/catalog-adapters');
    const adapter = new NewManifestAdapter();

    const rawManifest = {
      id: 'catalog-1',
      contracts: [
        {
          title: 'Missing image manager contract',
          slug: 'missing-image',
          manager_supported: true,
          config_schema: {
            type: 'object',
            properties: { key: { type: 'string' } },
            required: ['key'],
            additionalProperties: false,
          },
        },
      ],
    };

    expect(() => adapter.toPersistableContracts(rawManifest)).toThrow('Contract must define container_image field');
  });

  it('NewManifestAdapter.toPersistableContracts validates manager config schema syntax', async () => {
    const { NewManifestAdapter } = await import('../../../../src/modules/catalog/catalog-adapters');
    const adapter = new NewManifestAdapter();

    const rawManifest = {
      id: 'catalog-1',
      contracts: [
        {
          title: 'Invalid schema manager contract',
          slug: 'invalid-schema',
          manager_supported: true,
          image_name: 'opencti/invalid-schema:1.0.0',
          image_type: 'EXTERNAL_IMPORT',
          config_schema: {
            type: 'object',
            properties: {
              key: { type: 'not-a-real-json-schema-type' },
            },
            required: ['key'],
            additionalProperties: false,
          },
        },
      ],
    };

    expect(() => adapter.toPersistableContracts(rawManifest)).toThrow('Contract must be a valid json schema definition');
  });

  it('NewManifestAdapter.toPersistableContracts normalizes contracts and keeps all versions', async () => {
    const { NewManifestAdapter } = await import('../../../../src/modules/catalog/catalog-adapters');
    const adapter = new NewManifestAdapter();

    const rawManifest = {
      id: 'catalog-1',
      name: 'Catalog One',
      description: 'Desc',
      contracts: [
        {
          id: 'c1',
          title: 'IPInfo v1',
          slug: 'ipinfo',
          version: '1.0.0',
          image_name: 'opencti/ipinfo:1.0.0',
          verified: 'true',
          use_cases: ['enrichment', 12],
          additional_properties: {
            playbook_supported: 'true',
            max_confidence_level: '80',
          },
          config_schema: {
            properties: {
              key: { type: 'string' },
              opencti_uri: { type: 'string' },
              opencti_token: { type: 'string', format: 'password' },
            },
            required: ['key', 'opencti_uri', 'opencti_token'],
            additionalProperties: false,
          },
        },
        {
          id: 'c2',
          title: 'IPInfo v2',
          slug: 'ipinfo',
          version: '2.0.0',
          container_image: 'opencti/ipinfo:2.0.0',
        },
      ],
    };

    const contracts = adapter.toPersistableContracts(rawManifest);

    expect(contracts).toHaveLength(2);
    expect(contracts[0]).toEqual(expect.objectContaining({
      slug: 'ipinfo',
      container_version: '1.0.0',
      container_image: 'opencti/ipinfo:1.0.0',
      playbook_supported: true,
      max_confidence_level: 80,
      verified: true,
      use_cases: ['enrichment'],
      config_schema: expect.objectContaining({
        properties: { key: { type: 'string' } },
        required: ['key'],
        additionalProperties: false,
      }),
    }));

    expect(contracts[1]).toEqual(expect.objectContaining({
      slug: 'ipinfo',
      container_version: '2.0.0',
      container_image: 'opencti/ipinfo:2.0.0',
      container_type: 'EXTERNAL_IMPORT',
      playbook_supported: false,
      max_confidence_level: 100,
      verified: false,
      use_cases: [],
    }));
  });
});
