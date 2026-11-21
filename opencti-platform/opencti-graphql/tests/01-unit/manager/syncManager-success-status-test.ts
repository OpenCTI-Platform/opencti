import { beforeEach, describe, expect, it, vi } from 'vitest';
import { patchSync } from '../../../src/domain/connector';
import { getHttpClient } from '../../../src/utils/http-client';
import { wait } from '../../../src/database/utils';
import { syncManagerInstance } from '../../../src/manager/syncManager';

const mockSyncLogger = { info: vi.fn(), success: vi.fn(), error: vi.fn() };

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
});
vi.mock('../../../src/database/utils', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return { ...actual, wait: vi.fn(async () => {}) };
});
vi.mock('../../../src/domain/connector-sync-crypto', () => ({
  decryptSynchronizerCredential: vi.fn(),
}));
vi.mock('../../../src/utils/access', () => ({
  executionContext: vi.fn(() => ({})),
  SYSTEM_USER: { id: 'system' },
}));
vi.mock('../../../src/domain/connector', () => ({
  isSyncRunning: vi.fn(),
  patchSync: vi.fn(),
}));
vi.mock('../../../src/domain/status', () => ({
  resolveSyncedWorkflowId: vi.fn(),
}));
vi.mock('../../../src/modules/entitySetting/entitySetting-utils', () => ({
  getEntitySettingFromCache: vi.fn(),
}));
vi.mock('../../../src/lock/master-lock', () => ({
  lockResources: vi.fn(),
}));
vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn(async () => ({ internal_id: 'sync-id', name: 'sync', current_state_date: null })),
  topEntitiesList: vi.fn(async () => []),
}));
vi.mock('../../../src/database/rabbitmq', () => ({
  pushBundleToWorker: vi.fn(),
}));
vi.mock('../../../src/utils/http-client', () => ({
  getHttpClient: vi.fn(),
}));
vi.mock('../../../src/domain/connector-utils', () => ({
  createSyncHttpUri: vi.fn(() => 'http://remote/stream'),
  httpBase: vi.fn(),
}));
vi.mock('../../../src/database/stream/stream-utils', () => ({
  EVENT_CURRENT_VERSION: '1',
}));
vi.mock('../../../src/graphql/syncConsumerMetrics', () => ({
  clearSyncConsumerMetrics: vi.fn(async () => {}),
  storeSyncConsumerMetrics: vi.fn(),
}));
vi.mock('../../../src/manager/ingestionManager/ingestionManagerUtils', () => ({
  createIngestionLogger: () => mockSyncLogger,
  buildIngestionErrorMeta: vi.fn(() => ({})),
}));
vi.mock('../../../src/database/markdown-embedded-images', () => ({
  ALLOWED_EMBEDDED_IMAGE_MIME_TYPE_SET: new Set(),
  extractMarkdownImageReferences: vi.fn(() => []),
  MARKDOWN_FIELD_KEYS: [],
  resolveEmbeddedStoragePathWithContext: vi.fn(),
  rewriteMarkdownImageUrls: vi.fn((markdown: string) => ({ markdown })),
}));

const statusesWritten = () => vi.mocked(patchSync).mock.calls
  .map(([, , , patch]) => (patch as { last_execution_status?: string }).last_execution_status)
  .filter((status) => status !== undefined);

describe('syncManager connected handler - success status persistence', () => {
  let streamGet: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    // The remote stream only sends the connection event, then closes
    streamGet = vi.fn(async () => ({
      data: (async function* () {
        yield Buffer.from('event: connected\ndata: {"connectionId":"conn-1"}\n\n');
      })(),
    }));
    vi.mocked(getHttpClient).mockReturnValue({ get: streamGet } as never);
  });

  it('should retry a failed success write in place, without reconnecting nor reporting a failure', async () => {
    const instance = syncManagerInstance('sync-id');
    vi.mocked(patchSync)
      .mockRejectedValueOnce(new Error('storage unavailable'))
      .mockResolvedValue(undefined as never);
    mockSyncLogger.success.mockImplementation(async () => instance.stop());

    await instance.start({});

    expect(statusesWritten()).toEqual(['success', 'success']);
    expect(mockSyncLogger.success).toHaveBeenCalledTimes(1);
    expect(mockSyncLogger.success).toHaveBeenCalledWith('Feed execution succeeded', { connection_id: 'conn-1' });
    expect(mockSyncLogger.error).not.toHaveBeenCalled();
    expect(streamGet).toHaveBeenCalledTimes(1);
  });

  it('should stop retrying the success write when the sync is stopped', async () => {
    const instance = syncManagerInstance('sync-id');
    vi.mocked(patchSync).mockRejectedValue(new Error('storage unavailable'));
    vi.mocked(wait).mockImplementation(async () => instance.stop());

    await instance.start({});

    expect(statusesWritten()).toEqual(['success']);
    expect(mockSyncLogger.success).not.toHaveBeenCalled();
    expect(mockSyncLogger.error).not.toHaveBeenCalled();
    expect(streamGet).toHaveBeenCalledTimes(1);
  });
});
