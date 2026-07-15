import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual<typeof import('../../../../src/config/conf')>('../../../../src/config/conf');
  return {
    ...actual,
    default: {
      get: (key: string) => {
        if (key === 'xtm:xtmhub_url') return 'https://hub.example.test';
        return undefined;
      },
    },
    PLATFORM_VERSION: '7.999999.0',
  };
});

describe('resolveCatalogSource', () => {
  afterEach(() => {
    vi.resetModules();
  });

  it('returns default hub URL when uri is undefined', async () => {
    const { resolveCatalogSource } = await import('../../../../src/modules/catalog/catalog-adapters');
    const resolved = resolveCatalogSource(undefined);

    expect(resolved.source.kind).toBe('remote');
    expect(resolved.source.uri).toBe('https://hub.example.test/opencti/7.999999.0/connectors/manifests/latest');
  });

  it('returns default hub URL when uri is empty string', async () => {
    const { resolveCatalogSource } = await import('../../../../src/modules/catalog/catalog-adapters');
    const resolved = resolveCatalogSource('   ');

    expect(resolved.source.kind).toBe('remote');
    expect(resolved.source.uri).toBe('https://hub.example.test/opencti/7.999999.0/connectors/manifests/latest');
  });

  it('treats http and https as remote URLs', async () => {
    const { resolveCatalogSource } = await import('../../../../src/modules/catalog/catalog-adapters');

    expect(resolveCatalogSource('http://localhost:9999/manifest.json').source)
      .toEqual({ kind: 'remote', uri: 'http://localhost:9999/manifest.json' });
    expect(resolveCatalogSource('https://localhost:9999/manifest.json').source)
      .toEqual({ kind: 'remote', uri: 'https://localhost:9999/manifest.json' });
  });

  it('treats relative local path as local file resolved from cwd', async () => {
    const { resolveCatalogSource } = await import('../../../../src/modules/catalog/catalog-adapters');
    const resolved = resolveCatalogSource('./connector-catalog.json.local');

    expect(resolved.source.kind).toBe('local');
    expect(resolved.source.uri.endsWith('/connector-catalog.json.local')).toBeTruthy();
  });

  it('strips file:// prefix and resolves as local path', async () => {
    const { resolveCatalogSource } = await import('../../../../src/modules/catalog/catalog-adapters');
    const resolved = resolveCatalogSource('file:///tmp/catalog.json');

    expect(resolved.source).toEqual({ kind: 'local', uri: '/tmp/catalog.json' });
  });

  it('rejects unsupported URI schemes', async () => {
    const { resolveCatalogSource } = await import('../../../../src/modules/catalog/catalog-adapters');

    expect(() => resolveCatalogSource('ftp://example.test/manifest.json')).toThrow();
  });
});
