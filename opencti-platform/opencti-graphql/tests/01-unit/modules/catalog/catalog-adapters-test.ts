import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const confGetMock = vi.fn();
const readFileMock = vi.fn();
const buildInternalCatalogMock = vi.fn();

vi.mock('../../../../src/config/conf', () => ({
  __esModule: true,
  default: {
    get: (...args: unknown[]) => confGetMock(...args),
  },
  PLATFORM_VERSION: '7.260722.0',
}));

vi.mock('node:fs/promises', () => ({
  readFile: (...args: unknown[]) => readFileMock(...args),
}));

vi.mock('../../../../src/modules/catalog/catalog-cache', () => ({
  buildInternalCatalog: (...args: unknown[]) => buildInternalCatalogMock(...args),
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
    buildInternalCatalogMock.mockReturnValue({ built: true });
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

  it('LegacyManifestAdapter.fetch returns embedded + custom catalogs', async () => {
    confGetMock.mockImplementation((key: string) => {
      if (key === 'app:custom_catalogs') return ['/tmp/custom1.json', '/tmp/custom2.json'];
      if (key === 'xtm:xtmhub_url') return 'https://hub.filigran.io/';
      return undefined;
    });
    readFileMock.mockImplementation((filePath: string) => {
      if (filePath === '/tmp/custom1.json') {
        return JSON.stringify({ id: 'custom-1', contracts: [] });
      }
      if (filePath === '/tmp/custom2.json') {
        return JSON.stringify({ id: 'custom-2', contracts: [] });
      }
      throw new Error(`Unexpected file: ${filePath}`);
    });

    const { LegacyManifestAdapter } = await import('../../../../src/modules/catalog/catalog-adapters');
    const adapter = new LegacyManifestAdapter();

    const result = await adapter.fetch({ kind: 'local', uri: 'ignored' });

    expect(result).toEqual([
      expect.objectContaining({ id: 'embedded-catalog' }),
      { id: 'custom-1', contracts: [] },
      { id: 'custom-2', contracts: [] },
    ]);
    expect(readFileMock).toHaveBeenCalledTimes(2);
  });

  it('LegacyManifestAdapter.toInternalCatalog forwards definitions to buildInternalCatalog', async () => {
    const { LegacyManifestAdapter } = await import('../../../../src/modules/catalog/catalog-adapters');
    const adapter = new LegacyManifestAdapter();
    const definitions = [{ id: 'legacy', contracts: [] }];

    const result = adapter.toInternalCatalog(definitions);

    expect(buildInternalCatalogMock).toHaveBeenCalledWith(definitions);
    expect(result).toEqual({ built: true });
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

  it('NewManifestAdapter.toInternalCatalog validates required manifest fields', async () => {
    const { NewManifestAdapter } = await import('../../../../src/modules/catalog/catalog-adapters');
    const adapter = new NewManifestAdapter();

    expect(() => adapter.toInternalCatalog({ contracts: [] })).toThrow('Catalog manifest is missing required fields: id and contracts');
    expect(() => adapter.toInternalCatalog({ id: 'catalog-1', contracts: 'not-array' })).toThrow('Catalog manifest is missing required fields: id and contracts');
  });

  it('NewManifestAdapter.toInternalCatalog keeps latest contract per slug and passes all contracts as second arg', async () => {
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
            properties: { key: { type: 'string' } },
            required: ['key'],
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

    adapter.toInternalCatalog(rawManifest);

    expect(buildInternalCatalogMock).toHaveBeenCalledTimes(1);
    const [latestDefinitions, allContracts] = buildInternalCatalogMock.mock.calls[0];

    expect(Array.isArray(latestDefinitions)).toBe(true);
    expect(latestDefinitions).toHaveLength(1);
    expect(latestDefinitions[0].contracts).toHaveLength(1);
    expect(latestDefinitions[0].contracts[0]).toEqual(expect.objectContaining({
      id: 'c2',
      slug: 'ipinfo',
      container_version: '2.0.0',
      container_image: 'opencti/ipinfo:2.0.0',
      container_type: 'EXTERNAL_IMPORT',
      playbook_supported: false,
      max_confidence_level: 100,
      verified: false,
      use_cases: [],
    }));

    expect(allContracts).toHaveLength(2);
    expect(allContracts[0]).toEqual(expect.objectContaining({
      id: 'c1',
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
  });
});
