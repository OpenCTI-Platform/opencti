import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

const mockRawUpload = vi.fn();
const mockHttpClientGet = vi.fn();

vi.mock('../../../src/domain/connector-sync-crypto', () => ({
  decryptSynchronizerCredential: vi.fn(),
}));
vi.mock('../../../src/utils/access', () => ({
  executionContext: vi.fn(() => ({})),
  SYSTEM_USER: { id: 'system' },
}));
vi.mock('../../../src/domain/connector', () => ({
  patchSync: vi.fn(),
}));
vi.mock('../../../src/domain/status', () => ({
  resolveSyncedWorkflowId: vi.fn(),
}));
vi.mock('../../../src/modules/entitySetting/entitySetting-utils', () => ({
  getEntitySettingFromCache: vi.fn(async () => ({})),
}));
vi.mock('../../../src/lock/master-lock', () => ({
  lockResources: vi.fn(),
}));
vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn(),
  topEntitiesList: vi.fn(async () => []),
}));
vi.mock('../../../src/database/rabbitmq', () => ({
  pushToWorkerForConnector: vi.fn(),
}));
vi.mock('../../../src/utils/http-client', () => ({
  getHttpClient: vi.fn(),
}));
vi.mock('../../../src/domain/connector-utils', () => ({
  createSyncHttpUri: vi.fn(),
  httpBase: vi.fn(),
}));
vi.mock('../../../src/database/stream/stream-utils', () => ({
  EVENT_CURRENT_VERSION: '1',
}));
vi.mock('../../../src/graphql/syncConsumerMetrics', () => ({
  clearSyncConsumerMetrics: vi.fn(),
  storeSyncConsumerMetrics: vi.fn(),
}));
vi.mock('../../../src/database/markdown-embedded-images', () => ({
  ALLOWED_EMBEDDED_IMAGE_MIME_TYPE_SET: new Set(),
  extractMarkdownImageReferences: vi.fn(() => []),
  MARKDOWN_FIELD_KEYS: [],
  resolveEmbeddedStoragePathWithContext: vi.fn(),
  rewriteMarkdownImageUrls: vi.fn((markdown: string) => ({ markdown })),
}));
vi.mock('../../../src/database/raw-file-storage', () => ({
  rawUpload: (...args: unknown[]) => mockRawUpload(...args),
}));

const buildRemoteFileData = () => ({
  extensions: {
    [STIX_EXT_OCTI]: {
      id: 'entity--id',
      type: 'Report',
      files: [{ uri: 'http://remote/storage/get/import/Report/entity--id/report.pdf', name: 'report.pdf' }],
    },
  },
});

const sync = { uri: 'http://remote', internal_id: 'sync--id-1' };
const httpClient = { get: (...args: unknown[]) => mockHttpClientGet(...args) };

describe('syncManager transformDataWithReverseIdAndFilesData - file reference mode', () => {
  beforeEach(() => {
    mockHttpClientGet.mockReset();
    mockRawUpload.mockReset();
  });

  afterEach(() => {
    vi.doUnmock('../../../src/config/conf');
    vi.resetModules();
  });

  it('keeps the base64 fallback when reference mode is disabled', async () => {
    vi.doMock('../../../src/config/conf', async (importOriginal) => {
      const actual = await importOriginal() as Record<string, unknown>;
      return { ...actual, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE: false, logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() } };
    });
    mockHttpClientGet.mockResolvedValue({ data: Buffer.from('pdf-bytes') });
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const { data } = await transformDataWithReverseIdAndFilesData(sync, httpClient, buildRemoteFileData(), {});

    expect(mockRawUpload).not.toHaveBeenCalled();
    expect(data.extensions[STIX_EXT_OCTI].files[0].data).toBe(Buffer.from('pdf-bytes').toString('base64'));
    expect(data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key).toBeUndefined();
  });

  it('streams into sync/inflight and emits a storage key when reference mode is enabled', async () => {
    vi.doMock('../../../src/config/conf', async (importOriginal) => {
      const actual = await importOriginal() as Record<string, unknown>;
      return { ...actual, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE: true, logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() } };
    });
    const fakeStream = Symbol('stream');
    mockHttpClientGet.mockResolvedValue({ data: fakeStream });
    mockRawUpload.mockResolvedValue(undefined);
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const { data } = await transformDataWithReverseIdAndFilesData(sync, httpClient, buildRemoteFileData(), {});

    expect(mockHttpClientGet).toHaveBeenCalledWith(expect.any(String), { responseType: 'stream' });
    expect(mockRawUpload).toHaveBeenCalledWith(expect.stringMatching(/^sync\/inflight\/sync--id-1\/[0-9a-f]{32}\/content$/), fakeStream);
    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.x_opencti_storage_key).toMatch(/^sync\/inflight\/sync--id-1\/[0-9a-f]{32}\/content$/);
    expect(resultFile.data).toBeUndefined();
  });

  it('inlines small files as base64 even when reference mode is enabled, skipping the staging round-trip', async () => {
    vi.doMock('../../../src/config/conf', async (importOriginal) => {
      const actual = await importOriginal() as Record<string, unknown>;
      return { ...actual, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE: true, logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() } };
    });
    const { Readable } = await import('node:stream');
    const smallFileBytes = Buffer.from('tiny-pdf-bytes');
    mockHttpClientGet.mockResolvedValue({
      data: Readable.from([smallFileBytes]),
      headers: { 'content-length': String(smallFileBytes.length) },
    });
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const { data } = await transformDataWithReverseIdAndFilesData(sync, httpClient, buildRemoteFileData(), {});

    expect(mockRawUpload).not.toHaveBeenCalled();
    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.data).toBe(smallFileBytes.toString('base64'));
    expect(resultFile.x_opencti_storage_key).toBeUndefined();
  });

  it('uses reference mode once content-length reports a file above the size threshold', async () => {
    vi.doMock('../../../src/config/conf', async (importOriginal) => {
      const actual = await importOriginal() as Record<string, unknown>;
      return { ...actual, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE: true, logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() } };
    });
    const fakeStream = Symbol('stream');
    mockHttpClientGet.mockResolvedValue({ data: fakeStream, headers: { 'content-length': String(10 * 1024 * 1024) } });
    mockRawUpload.mockResolvedValue(undefined);
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const { data } = await transformDataWithReverseIdAndFilesData(sync, httpClient, buildRemoteFileData(), {});

    expect(mockRawUpload).toHaveBeenCalledWith(expect.stringMatching(/^sync\/inflight\/sync--id-1\/[0-9a-f]{32}\/content$/), fakeStream);
    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.x_opencti_storage_key).toBeDefined();
    expect(resultFile.data).toBeUndefined();
  });

  it('treats a missing/invalid content-length as large, never buffering an unbounded stream', async () => {
    vi.doMock('../../../src/config/conf', async (importOriginal) => {
      const actual = await importOriginal() as Record<string, unknown>;
      return { ...actual, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE: true, logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() } };
    });
    const fakeStream = Symbol('stream');
    mockHttpClientGet.mockResolvedValue({ data: fakeStream, headers: { 'content-length': 'not-a-number' } });
    mockRawUpload.mockResolvedValue(undefined);
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const { data } = await transformDataWithReverseIdAndFilesData(sync, httpClient, buildRemoteFileData(), {});

    expect(mockRawUpload).toHaveBeenCalled();
    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.x_opencti_storage_key).toBeDefined();
  });

  it('skips the file without crashing when the upload fails', async () => {
    vi.doMock('../../../src/config/conf', async (importOriginal) => {
      const actual = await importOriginal() as Record<string, unknown>;
      return { ...actual, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE: true, logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() } };
    });
    mockHttpClientGet.mockResolvedValue({ data: Symbol('stream') });
    mockRawUpload.mockRejectedValue(new Error('S3 unavailable'));
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const { data } = await transformDataWithReverseIdAndFilesData(sync, httpClient, buildRemoteFileData(), {});

    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.x_opencti_storage_key).toBeUndefined();
    expect(resultFile.data).toBeUndefined();
  });

  it('never lets the remote-controlled file name influence the storage key (no traversal via entityFile.name)', async () => {
    vi.doMock('../../../src/config/conf', async (importOriginal) => {
      const actual = await importOriginal() as Record<string, unknown>;
      return { ...actual, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE: true, logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() } };
    });
    mockHttpClientGet.mockResolvedValue({ data: Symbol('stream') });
    mockRawUpload.mockResolvedValue(undefined);
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const maliciousData = {
      extensions: {
        [STIX_EXT_OCTI]: {
          id: 'entity--id',
          type: 'Report',
          files: [{ uri: 'http://remote/storage/get/import/Report/entity--id/report.pdf', name: '../../sync/inflight/some-other-sync/x/content' }],
        },
      },
    };
    const { data } = await transformDataWithReverseIdAndFilesData(sync, httpClient, maliciousData, {});

    const [storageKey] = mockRawUpload.mock.calls[0];
    expect(storageKey).toMatch(/^sync\/inflight\/sync--id-1\/[0-9a-f]{32}\/content$/);
    expect(data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key).toEqual(storageKey);
  });

  it('generates a fresh, unguessable storage key per file, never derived from the remote file URI', async () => {
    // Security model: storage_key is the actual bearer-capability that gates copying a staged
    // file (see copyFileFromSyncReference's doc comment) -- the platform can't otherwise tell
    // "the real sync worker" apart from any other caller with edit rights on some entity, since
    // all opencti-worker traffic shares one platform-wide token. If the key's remoteFileId segment
    // were derived from fileUri (e.g. a hash of it), anyone who separately learns fileUri -- which
    // is not secret, it can appear in bundle content or logs -- could compute the same key
    // themselves without ever being this sync's worker. It must be independently random every time,
    // even for the exact same fileUri fetched twice.
    vi.doMock('../../../src/config/conf', async (importOriginal) => {
      const actual = await importOriginal() as Record<string, unknown>;
      return { ...actual, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE: true, logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() } };
    });
    mockHttpClientGet.mockResolvedValue({ data: Symbol('stream') });
    mockRawUpload.mockResolvedValue(undefined);
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const sameUriData = () => ({
      extensions: {
        [STIX_EXT_OCTI]: {
          id: 'entity--id',
          type: 'Report',
          files: [{ uri: 'http://remote/storage/get/import/Report/entity--id/report.pdf', name: 'report.pdf' }],
        },
      },
    });

    const first = await transformDataWithReverseIdAndFilesData(sync, httpClient, sameUriData(), {});
    const second = await transformDataWithReverseIdAndFilesData(sync, httpClient, sameUriData(), {});

    const firstKey = first.data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key;
    const secondKey = second.data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key;
    expect(firstKey).toMatch(/^sync\/inflight\/sync--id-1\/[0-9a-f]{32}\/content$/);
    expect(secondKey).toMatch(/^sync\/inflight\/sync--id-1\/[0-9a-f]{32}\/content$/);
    expect(firstKey).not.toEqual(secondKey);
  });
});
