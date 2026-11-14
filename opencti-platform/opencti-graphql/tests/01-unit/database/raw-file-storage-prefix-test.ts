import { describe, expect, it, vi } from 'vitest';

// `minio:bucket_prefix` is read from `conf` at module-load time, so each scenario resets the
// module registry and re-imports raw-file-storage with a stubbed conf. The S3 client is replaced
// by a recorder to assert on the exact keys sent to the storage, and on what comes back.
const loadModule = async (bucketPrefix: string, listing: Record<string, any> = {}) => {
  vi.resetModules();

  const sent: any[] = [];
  vi.doMock('../../../src/config/conf', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../src/config/conf')>();
    return {
      ...actual,
      default: {
        ...actual.default,
        get: (key: string) => (key === 'minio:bucket_prefix' ? bucketPrefix : actual.default.get(key)),
      },
    };
  });
  vi.doMock('../../../src/utils/awsSdk', () => ({
    setupAwsClient: () => ({
      send: (command: any) => {
        sent.push(command.input);
        return Promise.resolve(listing);
      },
    }),
    getRoleAssumerWithWebIdentity: vi.fn(),
  }));

  const storage = await import('../../../src/database/raw-file-storage');
  await storage.initializeFileStorageClient();
  return { storage, sent };
};

describe('S3 bucket prefix', () => {
  it('should leave keys untouched when no prefix is configured', async () => {
    const { storage } = await loadModule('');
    expect(storage.buildKey('import/global/file.json')).toEqual('import/global/file.json');
    expect(storage.stripKey('import/global/file.json')).toEqual('import/global/file.json');
  });

  it('should namespace keys and strip them back', async () => {
    const { storage } = await loadModule('opencti');
    expect(storage.buildKey('import/global/file.json')).toEqual('opencti/import/global/file.json');
    expect(storage.stripKey(storage.buildKey('import/global/file.json'))).toEqual('import/global/file.json');
    // A key that is not under the prefix (or shares only a name fragment) is returned as is
    expect(storage.stripKey('import/global/file.json')).toEqual('import/global/file.json');
    expect(storage.stripKey('opencti-other/import/file.json')).toEqual('opencti-other/import/file.json');
  });

  it('should tolerate surrounding slashes in the configured prefix', async () => {
    const { storage } = await loadModule('/opencti/');
    expect(storage.buildKey('export/file.json')).toEqual('opencti/export/file.json');
  });

  it('should send prefixed keys to the storage', async () => {
    const { storage, sent } = await loadModule('opencti');
    await storage.deleteFileFromStorage('import/global/file.json');
    await storage.getFileMetadata('import/global/file.json');
    expect(sent.map((input) => input.Key)).toEqual([
      'opencti/import/global/file.json',
      'opencti/import/global/file.json',
    ]);
  });

  it('should list under the prefix and return platform relative keys', async () => {
    const listing = {
      Prefix: 'opencti/import/',
      Contents: [{ Key: 'opencti/import/global/file.json', Size: 12 }],
      CommonPrefixes: [{ Prefix: 'opencti/import/global/' }],
      IsTruncated: false,
    };
    const { storage, sent } = await loadModule('opencti', listing);
    const response = await storage.rawListObjects('import/', false);
    expect(sent[0].Prefix).toEqual('opencti/import/');
    expect(response.Prefix).toEqual('import/');
    expect(response.Contents).toEqual([{ Key: 'import/global/file.json', Size: 12 }]);
    expect(response.CommonPrefixes).toEqual([{ Prefix: 'import/global/' }]);
  });
});
