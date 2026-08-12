import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

const mockResolveSyncedWorkflowId = vi.fn();
const mockGetEntitySettingFromCache = vi.fn();

// Mock every non-trivial dependency of syncManager.js so the module can be imported in isolation.
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
});
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
  resolveSyncedWorkflowId: (...args: unknown[]) => mockResolveSyncedWorkflowId(...args),
}));
vi.mock('../../../src/modules/entitySetting/entitySetting-utils', () => ({
  getEntitySettingFromCache: (...args: unknown[]) => mockGetEntitySettingFromCache(...args),
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

const buildRemoteData = (extensionOverrides: Record<string, unknown>) => ({
  extensions: {
    [STIX_EXT_OCTI]: {
      id: 'entity--id',
      type: 'Report',
      ...extensionOverrides,
    },
  },
});

describe('syncManager transformDataWithReverseIdAndFilesData - workflow status remap', () => {
  beforeEach(() => {
    // Opt-in toggle enabled by default for existing tests; overridden per-test where needed.
    mockGetEntitySettingFromCache.mockResolvedValue({ sync_workflow_status_by_name: true });
  });

  afterEach(() => {
    mockResolveSyncedWorkflowId.mockReset();
    mockGetEntitySettingFromCache.mockReset();
  });

  it('should remap the remote workflow status to the local id when a match is found', async () => {
    mockResolveSyncedWorkflowId.mockResolvedValue('local-status-id');
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const remoteData = buildRemoteData({
      workflow_id: 'remote-status-id',
      workflow_status_name: 'IN_PROGRESS',
      workflow_status_scope: 'Global',
    });
    const { data } = await transformDataWithReverseIdAndFilesData({ uri: 'http://remote' }, {}, remoteData, {});

    expect(mockResolveSyncedWorkflowId).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'Report', 'Global', 'IN_PROGRESS');
    expect(data.extensions[STIX_EXT_OCTI].workflow_id).toBe('local-status-id');
    expect(data.extensions[STIX_EXT_OCTI].workflow_status_name).toBeUndefined();
    expect(data.extensions[STIX_EXT_OCTI].workflow_status_scope).toBeUndefined();
  });

  it('should drop the workflow id when there is no local match', async () => {
    mockResolveSyncedWorkflowId.mockResolvedValue(undefined);
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const remoteData = buildRemoteData({
      workflow_id: 'remote-status-id',
      workflow_status_name: 'UNKNOWN_STATUS',
      workflow_status_scope: 'Global',
    });
    const { data } = await transformDataWithReverseIdAndFilesData({ uri: 'http://remote' }, {}, remoteData, {});

    expect(data.extensions[STIX_EXT_OCTI].workflow_id).toBeUndefined();
    expect(data.extensions[STIX_EXT_OCTI].workflow_status_name).toBeUndefined();
    expect(data.extensions[STIX_EXT_OCTI].workflow_status_scope).toBeUndefined();
  });

  it('should not attempt any resolution when there is no remote workflow id', async () => {
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const remoteData = buildRemoteData({});
    const { data } = await transformDataWithReverseIdAndFilesData({ uri: 'http://remote' }, {}, remoteData, {});

    expect(mockResolveSyncedWorkflowId).not.toHaveBeenCalled();
    expect(data.extensions[STIX_EXT_OCTI].workflow_id).toBeUndefined();
  });

  it('should not attempt resolution and should drop the workflow id when the entity type has not opted in', async () => {
    mockGetEntitySettingFromCache.mockResolvedValue({ sync_workflow_status_by_name: false });
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const remoteData = buildRemoteData({
      workflow_id: 'remote-status-id',
      workflow_status_name: 'IN_PROGRESS',
      workflow_status_scope: 'Global',
    });
    const { data } = await transformDataWithReverseIdAndFilesData({ uri: 'http://remote' }, {}, remoteData, {});

    expect(mockResolveSyncedWorkflowId).not.toHaveBeenCalled();
    expect(data.extensions[STIX_EXT_OCTI].workflow_id).toBeUndefined();
    expect(data.extensions[STIX_EXT_OCTI].workflow_status_name).toBeUndefined();
    expect(data.extensions[STIX_EXT_OCTI].workflow_status_scope).toBeUndefined();
  });

  it('should not attempt resolution when there is no entity setting configured for the type', async () => {
    mockGetEntitySettingFromCache.mockResolvedValue(undefined);
    const { transformDataWithReverseIdAndFilesData } = await import('../../../src/manager/syncManager');

    const remoteData = buildRemoteData({
      workflow_id: 'remote-status-id',
      workflow_status_name: 'IN_PROGRESS',
      workflow_status_scope: 'Global',
    });
    const { data } = await transformDataWithReverseIdAndFilesData({ uri: 'http://remote' }, {}, remoteData, {});

    expect(mockResolveSyncedWorkflowId).not.toHaveBeenCalled();
    expect(data.extensions[STIX_EXT_OCTI].workflow_id).toBeUndefined();
  });
});
