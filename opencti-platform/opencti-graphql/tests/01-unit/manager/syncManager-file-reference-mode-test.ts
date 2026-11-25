import { Readable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

const mockRawUpload = vi.fn();
const mockHttpClientGet = vi.fn();
const mockStreamClientGet = vi.fn();
const mockLogWarn = vi.fn();
const mockWait = vi.fn();
const mockPushBundleToWorker = vi.fn();
const mockGetHttpClient = vi.fn();
const mockStoreLoadById = vi.fn();
const mockSyncLogger = { info: vi.fn(), success: vi.fn(async () => {}), error: vi.fn(async () => {}) };

const { MockHttpClientError } = vi.hoisted(() => ({
  MockHttpClientError: class MockHttpClientError extends Error {},
}));

vi.mock('../../../src/domain/connector-sync-crypto', () => ({
  decryptSynchronizerCredential: vi.fn(),
}));
vi.mock('../../../src/utils/access', () => ({
  executionContext: vi.fn(() => ({})),
  SYSTEM_USER: { id: 'system' },
}));
vi.mock('../../../src/domain/connector', () => ({
  patchSync: vi.fn(async () => {}),
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
  storeLoadById: (...args: unknown[]) => mockStoreLoadById(...args),
  topEntitiesList: vi.fn(async () => []),
}));
vi.mock('../../../src/database/rabbitmq', () => ({
  pushBundleToWorker: (...args: unknown[]) => mockPushBundleToWorker(...args),
}));
vi.mock('../../../src/utils/http-client', () => ({
  getHttpClient: (...args: unknown[]) => mockGetHttpClient(...args),
  HttpClientError: MockHttpClientError,
}));
vi.mock('../../../src/domain/connector-utils', () => ({
  createSyncHttpUri: vi.fn(() => SSE_URI),
  httpBase: vi.fn(),
}));
vi.mock('../../../src/manager/ingestionManager/ingestionManagerUtils', () => ({
  createIngestionLogger: () => mockSyncLogger,
  buildIngestionErrorMeta: vi.fn(() => ({})),
}));
vi.mock('../../../src/database/stream/stream-utils', () => ({
  EVENT_CURRENT_VERSION: '1',
}));
vi.mock('../../../src/graphql/syncConsumerMetrics', () => ({
  clearSyncConsumerMetrics: vi.fn(async () => {}),
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
vi.mock('../../../src/database/utils', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return { ...actual, wait: (...args: unknown[]) => mockWait(...args) };
});

const STAGED_KEY_PATTERN = /^sync\/inflight\/sync--id-1\/[0-9a-f]{32}\/content$/;
const FILE_URI = 'http://remote/storage/get/import/Report/entity--id/report.pdf';
const LARGE_CONTENT_LENGTH = String(10 * 1024 * 1024);
const SSE_URI = 'http://remote/stream';
const CONNECTED_EVENT = 'event: connected\ndata: {"connectionId":"conn-1"}\n\n';

interface ConfReader {
  get: (key: string) => unknown;
}

interface ConfMockOptions {
  isReferenceModeEnabled: boolean;
  thresholdKb?: number;
  maxSizeMb?: number;
}

interface RemoteFile {
  uri: string;
  name: string;
  data?: string;
  x_opencti_storage_key?: string;
}

interface RemoteOctiExtension {
  id: string;
  type: string;
  files: RemoteFile[];
}

interface RemoteFileData {
  extensions: Record<string, RemoteOctiExtension>;
}

interface StreamResponseHeaders {
  'content-length'?: string;
}

interface StreamResponse {
  data: unknown;
  headers: StreamResponseHeaders;
}

interface TestHttpClient {
  get: (...args: unknown[]) => unknown;
}

interface TestFileStaging {
  streamClient: TestHttpClient;
  stagedKeys: Map<number, string>;
  isStagingEvent: boolean;
}

interface TestSync {
  uri: string;
  internal_id: string;
}

interface TransformRequest {
  sync: TestSync;
  httpClient: TestHttpClient;
  data: RemoteFileData;
  context: object;
  fileStaging: TestFileStaging | undefined;
}

interface PushedBundle {
  content: string;
}

interface PushedEventPayload {
  data: RemoteFileData;
}

const sync: TestSync = { uri: 'http://remote', internal_id: 'sync--id-1' };
const httpClient: TestHttpClient = { get: (...args: unknown[]) => mockHttpClientGet(...args) };
const streamClient: TestHttpClient = { get: (...args: unknown[]) => mockStreamClientGet(...args) };

const buildReportFile = (): RemoteFile => ({ uri: FILE_URI, name: 'report.pdf' });

const buildRemoteFileData = (file: RemoteFile, entityType: string): RemoteFileData => ({
  extensions: {
    [STIX_EXT_OCTI]: {
      id: 'entity--id',
      type: entityType,
      files: [file],
    },
  },
});

const buildFileStaging = (isStagingEvent: boolean): TestFileStaging => ({ streamClient, stagedKeys: new Map(), isStagingEvent });

const buildRequest = (data: RemoteFileData, fileStaging: TestFileStaging | undefined): TransformRequest => ({
  sync,
  httpClient,
  data,
  context: {},
  fileStaging,
});

const largeFileResponse = (stream: unknown): StreamResponse => ({ data: stream, headers: { 'content-length': LARGE_CONTENT_LENGTH } });

const serveFreshLargeFiles = (): Readable[] => {
  const servedStreams: Readable[] = [];
  mockStreamClientGet.mockImplementation(async () => {
    const fileStream = Readable.from([Buffer.from('large-pdf-bytes')]);
    servedStreams.push(fileStream);
    return largeFileResponse(fileStream);
  });
  return servedStreams;
};

const buildCreateEvent = (data: RemoteFileData) => {
  const eventData = JSON.stringify({ data, context: {}, version: '1', event_id: 'event-1' });
  return `id: 1700000000000-0\nevent: create\ndata: ${eventData}\n\n`;
};

// Serves the sync stream on SSE_URI and every other URI as a file download.
const buildSyncHttpClient = (createEvent: string): TestHttpClient => ({
  get: (...args: unknown[]) => {
    const isStreamRequest = args[0] === SSE_URI;
    if (isStreamRequest) {
      const streamResponse: StreamResponse = { data: Readable.from([Buffer.from(CONNECTED_EVENT), Buffer.from(createEvent)]), headers: {} };
      return Promise.resolve(streamResponse);
    }
    return mockStreamClientGet(...args);
  },
});

const pushedStorageKey = (pushCall: unknown[]) => {
  const bundle = pushCall[3] as PushedBundle;
  const payload = JSON.parse(Buffer.from(bundle.content, 'base64').toString()) as PushedEventPayload;
  return payload.data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key;
};

const readBody = async (body: AsyncIterable<Buffer>) => {
  const chunks: Buffer[] = [];
  for await (const chunk of body) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
};

const mockConf = (options: ConfMockOptions) => {
  vi.doMock('../../../src/config/conf', async (importOriginal) => {
    const actual = await importOriginal() as Record<string, unknown>;
    const actualConf = actual.default as ConfReader;
    const conf: ConfReader = {
      get: (key: string) => {
        const isThresholdKey = key === 'sync_manager:file_reference_mode_size_threshold_kb';
        if (isThresholdKey && options.thresholdKb !== undefined) {
          return options.thresholdKb;
        }
        const isMaxSizeKey = key === 'sync_manager:file_reference_mode_max_size_mb';
        if (isMaxSizeKey && options.maxSizeMb !== undefined) {
          return options.maxSizeMb;
        }
        return actualConf.get(key);
      },
    };
    const logApp = { info: vi.fn(), debug: vi.fn(), warn: mockLogWarn, error: vi.fn() };
    return { ...actual, default: conf, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE: options.isReferenceModeEnabled, logApp };
  });
};

const loadTransform = async () => {
  const syncManager = await import('../../../src/manager/syncManager');
  return syncManager.transformDataWithReverseIdAndFilesData;
};

describe('syncManager transformDataWithReverseIdAndFilesData - file reference mode', () => {
  beforeEach(() => {
    mockHttpClientGet.mockReset();
    mockStreamClientGet.mockReset();
    mockRawUpload.mockReset();
    mockLogWarn.mockReset();
    mockWait.mockReset();
    mockPushBundleToWorker.mockReset();
    mockGetHttpClient.mockReset();
    mockStoreLoadById.mockReset();
  });

  afterEach(() => {
    vi.doUnmock('../../../src/config/conf');
    vi.resetModules();
  });

  it('keeps the base64 path when reference mode is disabled', async () => {
    mockConf({ isReferenceModeEnabled: false });
    mockHttpClientGet.mockResolvedValue({ data: Buffer.from('pdf-bytes') });
    const transform = await loadTransform();

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), undefined));

    expect(mockStreamClientGet).not.toHaveBeenCalled();
    expect(mockRawUpload).not.toHaveBeenCalled();
    expect(data.extensions[STIX_EXT_OCTI].files[0].data).toBe(Buffer.from('pdf-bytes').toString('base64'));
    expect(data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key).toBeUndefined();
  });

  it('leaves the file entries as master does when reference mode is disabled', async () => {
    mockConf({ isReferenceModeEnabled: false });
    mockHttpClientGet.mockResolvedValue({ data: Buffer.from('pdf-bytes') });
    const transform = await loadTransform();
    const remoteFile: RemoteFile = { uri: FILE_URI, name: 'report.pdf', x_opencti_storage_key: 'sync/inflight/sync--id-1/0123/content' };

    const { data } = await transform(buildRequest(buildRemoteFileData(remoteFile, 'Report'), undefined));

    expect(data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key).toBe('sync/inflight/sync--id-1/0123/content');
  });

  it('drops a storage key sent by the sending platform even when the file URI is invalid', async () => {
    mockConf({ isReferenceModeEnabled: true });
    const transform = await loadTransform();
    const remoteFile: RemoteFile = { uri: 'not-a-storage-uri', name: 'report.pdf', x_opencti_storage_key: 'sync/inflight/sync--id-1/0123/content' };

    const { data } = await transform(buildRequest(buildRemoteFileData(remoteFile, 'Report'), buildFileStaging(true)));

    expect(mockStreamClientGet).not.toHaveBeenCalled();
    expect(data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key).toBeUndefined();
  });

  it('streams a large file into sync/inflight and sends its storage key when reference mode is enabled', async () => {
    mockConf({ isReferenceModeEnabled: true });
    const fakeStream = Symbol('stream');
    mockStreamClientGet.mockResolvedValue(largeFileResponse(fakeStream));
    mockRawUpload.mockResolvedValue(undefined);
    const transform = await loadTransform();

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(true)));

    expect(mockHttpClientGet).not.toHaveBeenCalled();
    expect(mockRawUpload).toHaveBeenCalledWith(expect.stringMatching(STAGED_KEY_PATTERN), expect.any(Readable));
    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.x_opencti_storage_key).toMatch(STAGED_KEY_PATTERN);
    expect(resultFile.data).toBeUndefined();
  });

  it('reuses the staged key when the same event is transformed again after a failed push', async () => {
    mockConf({ isReferenceModeEnabled: true });
    mockStreamClientGet.mockResolvedValue(largeFileResponse(Symbol('stream')));
    mockRawUpload.mockResolvedValue(undefined);
    const transform = await loadTransform();
    const remoteData = buildRemoteFileData(buildReportFile(), 'Report');
    const fileStaging = buildFileStaging(true);

    const firstAttempt = await transform(buildRequest(remoteData, fileStaging));
    const firstKey = firstAttempt.data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key;
    const secondAttempt = await transform(buildRequest(remoteData, fileStaging));
    const secondKey = secondAttempt.data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key;

    expect(mockStreamClientGet).toHaveBeenCalledTimes(1);
    expect(mockRawUpload).toHaveBeenCalledTimes(1);
    expect(firstKey).toMatch(STAGED_KEY_PATTERN);
    expect(secondKey).toEqual(firstKey);
  });

  it('uploads a staged file once and pushes the same key again when the first push fails', async () => {
    mockConf({ isReferenceModeEnabled: true });
    mockStoreLoadById.mockResolvedValue(sync);
    mockGetHttpClient.mockReturnValue(buildSyncHttpClient(buildCreateEvent(buildRemoteFileData(buildReportFile(), 'Report'))));
    serveFreshLargeFiles();
    mockRawUpload.mockResolvedValue(undefined);
    const syncManager = await import('../../../src/manager/syncManager');
    const instance = syncManager.syncManagerInstance(sync.internal_id);
    mockPushBundleToWorker
      .mockRejectedValueOnce(new Error('RabbitMQ unavailable'))
      .mockImplementationOnce(async () => instance.stop());

    await instance.start({});

    expect(mockStreamClientGet).toHaveBeenCalledTimes(1);
    expect(mockRawUpload).toHaveBeenCalledTimes(1);
    expect(mockPushBundleToWorker).toHaveBeenCalledTimes(2);
    const [firstPush, secondPush] = mockPushBundleToWorker.mock.calls;
    expect(pushedStorageKey(firstPush)).toMatch(STAGED_KEY_PATTERN);
    expect(pushedStorageKey(secondPush)).toEqual(pushedStorageKey(firstPush));
  });

  it('creates no file stream client and inlines the file when reference mode is disabled', async () => {
    mockConf({ isReferenceModeEnabled: false });
    mockStoreLoadById.mockResolvedValue(sync);
    mockGetHttpClient.mockReturnValue(buildSyncHttpClient(buildCreateEvent(buildRemoteFileData(buildReportFile(), 'Report'))));
    mockStreamClientGet.mockResolvedValue({ data: Buffer.from('pdf-bytes'), headers: {} });
    const syncManager = await import('../../../src/manager/syncManager');
    const instance = syncManager.syncManagerInstance(sync.internal_id);
    mockPushBundleToWorker.mockImplementationOnce(async () => instance.stop());

    await instance.start({});

    const fileStreamClientOptions = expect.objectContaining({ responseType: 'stream', timeout: expect.any(Number) });
    expect(mockGetHttpClient).not.toHaveBeenCalledWith(fileStreamClientOptions);
    expect(mockRawUpload).not.toHaveBeenCalled();
    expect(pushedStorageKey(mockPushBundleToWorker.mock.calls[0])).toBeUndefined();
  });

  it('inlines a large file as base64 as today for an event that is not a create or an update', async () => {
    mockConf({ isReferenceModeEnabled: true, thresholdKb: 1 });
    const fileChunks = [Buffer.alloc(700, 'a'), Buffer.alloc(700, 'b'), Buffer.alloc(700, 'c')];
    mockStreamClientGet.mockResolvedValue({ data: Readable.from(fileChunks), headers: {} });
    const transform = await loadTransform();

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(false)));

    expect(mockRawUpload).not.toHaveBeenCalled();
    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.x_opencti_storage_key).toBeUndefined();
    expect(resultFile.data).toBe(Buffer.concat(fileChunks).toString('base64'));
  });

  it('inlines a large file of an external reference as base64 as today', async () => {
    mockConf({ isReferenceModeEnabled: true });
    const largeFileBytes = Buffer.from('large-pdf-bytes');
    mockStreamClientGet.mockResolvedValue(largeFileResponse(Readable.from([largeFileBytes])));
    const transform = await loadTransform();
    const remoteData = buildRemoteFileData(buildReportFile(), 'External-Reference');

    const { data } = await transform(buildRequest(remoteData, buildFileStaging(true)));

    expect(mockRawUpload).not.toHaveBeenCalled();
    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.x_opencti_storage_key).toBeUndefined();
    expect(resultFile.data).toBe(largeFileBytes.toString('base64'));
  });

  it('inlines a small file as base64 even when reference mode is enabled', async () => {
    mockConf({ isReferenceModeEnabled: true });
    const smallFileBytes = Buffer.from('tiny-pdf-bytes');
    mockStreamClientGet.mockResolvedValue({ data: Readable.from([smallFileBytes]), headers: { 'content-length': String(smallFileBytes.length) } });
    const transform = await loadTransform();

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(true)));

    expect(mockRawUpload).not.toHaveBeenCalled();
    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.data).toBe(smallFileBytes.toString('base64'));
    expect(resultFile.x_opencti_storage_key).toBeUndefined();
  });

  it('inlines a small file of a delete event as today', async () => {
    mockConf({ isReferenceModeEnabled: true });
    const smallFileBytes = Buffer.from('tiny-pdf-bytes');
    mockStreamClientGet.mockResolvedValue({ data: Readable.from([smallFileBytes]), headers: {} });
    const transform = await loadTransform();

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(false)));

    expect(data.extensions[STIX_EXT_OCTI].files[0].data).toBe(smallFileBytes.toString('base64'));
  });

  it('stages every non-empty file when the size threshold is configured to 0', async () => {
    mockConf({ isReferenceModeEnabled: true, thresholdKb: 0 });
    const fakeStream = Symbol('stream');
    mockStreamClientGet.mockResolvedValue({ data: fakeStream, headers: { 'content-length': '1' } });
    mockRawUpload.mockResolvedValue(undefined);
    const transform = await loadTransform();

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(true)));

    expect(mockRawUpload).toHaveBeenCalledWith(expect.stringMatching(STAGED_KEY_PATTERN), expect.any(Readable));
    expect(data.extensions[STIX_EXT_OCTI].files[0].data).toBeUndefined();
  });

  it('inlines a small file when the sending platform sends no content-length', async () => {
    mockConf({ isReferenceModeEnabled: true });
    const smallFileBytes = Buffer.from('tiny-pdf-bytes');
    mockStreamClientGet.mockResolvedValue({ data: Readable.from([smallFileBytes]), headers: {} });
    const transform = await loadTransform();

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(true)));

    expect(mockRawUpload).not.toHaveBeenCalled();
    expect(data.extensions[STIX_EXT_OCTI].files[0].data).toBe(smallFileBytes.toString('base64'));
  });

  it('stages every byte of a file above the threshold when content-length is missing or invalid', async () => {
    mockConf({ isReferenceModeEnabled: true, thresholdKb: 1 });
    const fileChunks = [Buffer.alloc(700, 'a'), Buffer.alloc(700, 'b'), Buffer.alloc(700, 'c')];
    mockStreamClientGet.mockResolvedValue({ data: Readable.from(fileChunks), headers: { 'content-length': 'not-a-number' } });
    const uploadedBodies: Buffer[] = [];
    mockRawUpload.mockImplementation(async (_key: string, body: AsyncIterable<Buffer>) => {
      uploadedBodies.push(await readBody(body));
    });
    const transform = await loadTransform();

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(true)));

    expect(uploadedBodies).toEqual([Buffer.concat(fileChunks)]);
    expect(data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key).toMatch(STAGED_KEY_PATTERN);
    expect(data.extensions[STIX_EXT_OCTI].files[0].data).toBeUndefined();
  });

  it('skips the file after the staging upload fails 4 times with 1 s, 2 s and 4 s backoff', async () => {
    mockConf({ isReferenceModeEnabled: true });
    const servedStreams = serveFreshLargeFiles();
    mockRawUpload.mockRejectedValue(new Error('S3 unavailable'));
    const transform = await loadTransform();
    const fileStaging = buildFileStaging(true);

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), fileStaging));

    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.x_opencti_storage_key).toBeUndefined();
    expect(resultFile.data).toBeUndefined();
    expect(mockStreamClientGet).toHaveBeenCalledTimes(4);
    expect(mockRawUpload).toHaveBeenCalledTimes(4);
    expect(mockWait.mock.calls).toEqual([[1000], [2000], [4000]]);
    expect(servedStreams.every((fileStream) => fileStream.destroyed)).toBe(true);
    expect(fileStaging.stagedKeys.size).toBe(0);
    expect(mockLogWarn).toHaveBeenCalledWith(expect.stringContaining('Skipping file'), expect.objectContaining({ fileUri: FILE_URI }));
  });

  it('closes the sending platform stream of every attempt when the upload fails after a bounded read', async () => {
    mockConf({ isReferenceModeEnabled: true, thresholdKb: 1 });
    const servedStreams: Readable[] = [];
    mockStreamClientGet.mockImplementation(async () => {
      const fileStream = Readable.from([Buffer.alloc(700, 'a'), Buffer.alloc(700, 'b'), Buffer.alloc(700, 'c')]);
      servedStreams.push(fileStream);
      return { data: fileStream, headers: {} };
    });
    mockRawUpload.mockRejectedValue(new Error('S3 unavailable'));
    const transform = await loadTransform();

    await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(true)));

    expect(servedStreams).toHaveLength(4);
    expect(servedStreams.every((fileStream) => fileStream.destroyed)).toBe(true);
  });

  it('never puts the storage key in the warning of a failed upload', async () => {
    mockConf({ isReferenceModeEnabled: true });
    serveFreshLargeFiles();
    mockRawUpload.mockImplementation(async (key: string) => {
      throw new Error(`Exceeded 10000 parts in multipart upload to Bucket: test Key: ${key}.`);
    });
    const transform = await loadTransform();

    await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(true)));

    expect(mockLogWarn).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ message: expect.stringContaining('Sync file staging upload failed') }));
    expect(JSON.stringify(mockLogWarn.mock.calls)).not.toContain('sync/inflight');
  });

  it('stages the file on the second attempt after one failed upload', async () => {
    mockConf({ isReferenceModeEnabled: true });
    serveFreshLargeFiles();
    mockRawUpload.mockRejectedValueOnce(new Error('S3 unavailable')).mockResolvedValue(undefined);
    const transform = await loadTransform();
    const fileStaging = buildFileStaging(true);

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), fileStaging));

    const [[failedKey], [stagedKey]] = mockRawUpload.mock.calls;
    expect(data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key).toEqual(stagedKey);
    expect(stagedKey).toMatch(STAGED_KEY_PATTERN);
    expect(stagedKey).not.toEqual(failedKey);
    expect(mockStreamClientGet).toHaveBeenCalledTimes(2);
    expect(mockWait.mock.calls).toEqual([[1000]]);
    expect(fileStaging.stagedKeys.size).toBe(1);
  });

  it('stops retrying and skips the file when a later attempt fails on the sending platform', async () => {
    mockConf({ isReferenceModeEnabled: true });
    mockStreamClientGet
      .mockResolvedValueOnce(largeFileResponse(Readable.from([Buffer.from('large-pdf-bytes')])))
      .mockRejectedValueOnce(new MockHttpClientError('Request failed with status code 503'));
    mockRawUpload.mockRejectedValue(new Error('S3 unavailable'));
    const transform = await loadTransform();

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(true)));

    expect(data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key).toBeUndefined();
    expect(mockStreamClientGet).toHaveBeenCalledTimes(2);
    expect(mockRawUpload).toHaveBeenCalledTimes(1);
    expect(mockWait.mock.calls).toEqual([[1000]]);
    expect(mockLogWarn).toHaveBeenCalledWith(expect.stringContaining('Skipping file'), expect.objectContaining({ message: 'Request failed with status code 503' }));
  });

  it('skips the file as today when the sending platform stream breaks during the upload', async () => {
    mockConf({ isReferenceModeEnabled: true, thresholdKb: 1 });
    const brokenSource = async function* () {
      yield Buffer.alloc(1500, 'a');
      throw new MockHttpClientError('timeout of 300000ms exceeded');
    };
    const fileStream = Readable.from(brokenSource(), { objectMode: false });
    mockStreamClientGet.mockResolvedValue({ data: fileStream, headers: {} });
    mockRawUpload.mockImplementation(async (_key: string, body: AsyncIterable<Buffer>) => {
      await readBody(body);
    });
    const transform = await loadTransform();
    const fileStaging = buildFileStaging(true);

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), fileStaging));

    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.x_opencti_storage_key).toBeUndefined();
    expect(resultFile.data).toBeUndefined();
    expect(fileStaging.stagedKeys.size).toBe(0);
    expect(mockStreamClientGet).toHaveBeenCalledTimes(1);
    expect(mockWait).not.toHaveBeenCalled();
  });

  it('skips a file above the staging size limit and aborts its upload', async () => {
    mockConf({ isReferenceModeEnabled: true, thresholdKb: 1, maxSizeMb: 1 });
    const fileStream = Readable.from([Buffer.alloc(512 * 1024, 'a'), Buffer.alloc(512 * 1024, 'b'), Buffer.alloc(512 * 1024, 'c')]);
    mockStreamClientGet.mockResolvedValue({ data: fileStream, headers: {} });
    mockRawUpload.mockImplementation(async (_key: string, body: AsyncIterable<Buffer>) => {
      await readBody(body);
    });
    const transform = await loadTransform();
    const fileStaging = buildFileStaging(true);

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), fileStaging));

    const resultFile = data.extensions[STIX_EXT_OCTI].files[0];
    expect(resultFile.x_opencti_storage_key).toBeUndefined();
    expect(resultFile.data).toBeUndefined();
    expect(fileStaging.stagedKeys.size).toBe(0);
    expect(fileStream.destroyed).toBe(true);
    expect(mockLogWarn).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ message: expect.stringContaining('1 MB') }));
    expect(mockStreamClientGet).toHaveBeenCalledTimes(1);
    expect(mockWait).not.toHaveBeenCalled();
  });

  it('stages a file at exactly the staging size limit', async () => {
    mockConf({ isReferenceModeEnabled: true, thresholdKb: 1, maxSizeMb: 1 });
    const fileChunks = [Buffer.alloc(512 * 1024, 'a'), Buffer.alloc(512 * 1024, 'b')];
    mockStreamClientGet.mockResolvedValue({ data: Readable.from(fileChunks), headers: {} });
    const uploadedBodies: Buffer[] = [];
    mockRawUpload.mockImplementation(async (_key: string, body: AsyncIterable<Buffer>) => {
      uploadedBodies.push(await readBody(body));
    });
    const transform = await loadTransform();

    const { data } = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(true)));

    expect(uploadedBodies).toEqual([Buffer.concat(fileChunks)]);
    expect(data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key).toMatch(STAGED_KEY_PATTERN);
  });

  it('never lets the remote file name influence the storage key', async () => {
    mockConf({ isReferenceModeEnabled: true });
    mockStreamClientGet.mockResolvedValue(largeFileResponse(Symbol('stream')));
    mockRawUpload.mockResolvedValue(undefined);
    const transform = await loadTransform();
    const remoteFile: RemoteFile = { uri: FILE_URI, name: '../../sync/inflight/some-other-sync/x/content' };

    const { data } = await transform(buildRequest(buildRemoteFileData(remoteFile, 'Report'), buildFileStaging(true)));

    const [storageKey] = mockRawUpload.mock.calls[0];
    expect(storageKey).toMatch(STAGED_KEY_PATTERN);
    expect(data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key).toEqual(storageKey);
  });

  it('generates a fresh random storage key for each event, never derived from the remote file URI', async () => {
    mockConf({ isReferenceModeEnabled: true });
    mockStreamClientGet.mockResolvedValue(largeFileResponse(Symbol('stream')));
    mockRawUpload.mockResolvedValue(undefined);
    const transform = await loadTransform();

    const first = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(true)));
    const second = await transform(buildRequest(buildRemoteFileData(buildReportFile(), 'Report'), buildFileStaging(true)));

    const firstKey = first.data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key;
    const secondKey = second.data.extensions[STIX_EXT_OCTI].files[0].x_opencti_storage_key;
    expect(firstKey).toMatch(STAGED_KEY_PATTERN);
    expect(secondKey).toMatch(STAGED_KEY_PATTERN);
    expect(firstKey).not.toEqual(secondKey);
  });
});
