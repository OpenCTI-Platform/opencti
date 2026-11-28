import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ManagerDefinition } from '../../../src/manager/managerModule';

const mockRawListObjects = vi.fn();
const mockDeleteFileFromStorage = vi.fn();
const mockRegisterManager = vi.fn<(definition: ManagerDefinition) => void>();
const mockLogWarn = vi.fn();
const DAY_MS = 24 * 60 * 60 * 1000;

vi.mock('../../../src/manager/managerModule', () => ({
  registerManager: (definition: ManagerDefinition) => mockRegisterManager(definition),
}));
vi.mock('../../../src/database/raw-file-storage', () => ({
  rawListObjects: (...args: unknown[]) => mockRawListObjects(...args),
  deleteFileFromStorage: (...args: unknown[]) => mockDeleteFileFromStorage(...args),
}));

type BooleanConf = (key: string, defaultValue: boolean) => boolean;

interface CleanupConfMockOptions {
  isReferenceModeEnabled: boolean;
  enabledOverride?: boolean;
}

const mockConf = (options: CleanupConfMockOptions) => {
  vi.doMock('../../../src/config/conf', async (importOriginal) => {
    const actual = await importOriginal() as Record<string, unknown>;
    const actualBooleanConf = actual.booleanConf as BooleanConf;
    const booleanConf: BooleanConf = (key, defaultValue) => {
      const isOverridden = key === 'sync_inflight_cleanup_manager:enabled' && options.enabledOverride !== undefined;
      if (isOverridden) {
        return options.enabledOverride as boolean;
      }
      return actualBooleanConf(key, defaultValue);
    };
    const logApp = { info: vi.fn(), debug: vi.fn(), warn: mockLogWarn, error: vi.fn() };
    return { ...actual, booleanConf, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE: options.isReferenceModeEnabled, logApp };
  });
};

const loadHandler = async () => {
  const manager = await import('../../../src/manager/syncInflightCleanupManager');
  return manager.syncInflightCleanupHandler;
};

// The logger keeps the message and stack of an Error, which plain JSON.stringify drops.
const serializeLogMeta = (meta: unknown) => JSON.stringify(meta, (_key: string, value: unknown) => {
  if (value instanceof Error) {
    return { name: value.name, message: value.message, stack: value.stack };
  }
  return value;
});

const registeredEnabledByConfig = () => {
  const [definition] = mockRegisterManager.mock.calls[0];
  return definition.enabledByConfig;
};

describe('sync inflight cleanup manager', () => {
  beforeEach(() => {
    vi.resetModules();
    mockRawListObjects.mockReset();
    mockDeleteFileFromStorage.mockReset();
    mockRegisterManager.mockReset();
    mockLogWarn.mockReset();
  });

  afterEach(() => {
    vi.doUnmock('../../../src/config/conf');
  });

  it('is not registered with the default configuration', async () => {
    vi.doUnmock('../../../src/config/conf');
    await import('../../../src/manager/syncInflightCleanupManager');

    expect(mockRegisterManager).not.toHaveBeenCalled();
  });

  it('follows file reference mode when its own enabled setting is not set', async () => {
    mockConf({ isReferenceModeEnabled: true });
    await import('../../../src/manager/syncInflightCleanupManager');

    expect(registeredEnabledByConfig()).toBe(true);
  });

  it('keeps running after file reference mode is turned off when enabled explicitly, to drain staged files', async () => {
    mockConf({ isReferenceModeEnabled: false, enabledOverride: true });
    await import('../../../src/manager/syncInflightCleanupManager');

    expect(registeredEnabledByConfig()).toBe(true);
  });

  it('deletes only sync/inflight objects older than the TTL', async () => {
    mockConf({ isReferenceModeEnabled: true });
    const now = Date.now();
    const oldKey = 'sync/inflight/sync-id-1/file-1/content';
    const recentKey = 'sync/inflight/sync-id-2/file-2/content';
    mockRawListObjects.mockResolvedValue({
      Contents: [
        { Key: oldKey, LastModified: new Date(now - (8 * DAY_MS)) },
        { Key: recentKey, LastModified: new Date(now - (60 * 1000)) },
      ],
      IsTruncated: false,
    });
    const handler = await loadHandler();

    await handler();

    expect(mockRawListObjects).toHaveBeenCalledWith('sync/inflight/', true, undefined);
    expect(mockDeleteFileFromStorage).toHaveBeenCalledTimes(1);
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith(oldKey);
  });

  it('keeps a staged file younger than the default TTL of one week, so a worker backlog can still consume it', async () => {
    mockConf({ isReferenceModeEnabled: true });
    mockRawListObjects.mockResolvedValue({
      Contents: [{ Key: 'sync/inflight/sync-id-7/file-7/content', LastModified: new Date(Date.now() - (6 * DAY_MS)) }],
      IsTruncated: false,
    });
    const handler = await loadHandler();

    await handler();

    expect(mockDeleteFileFromStorage).not.toHaveBeenCalled();
  });

  it('pages through the listing with the continuation token', async () => {
    mockConf({ isReferenceModeEnabled: true });
    const now = Date.now();
    const oldKeyPage1 = 'sync/inflight/sync-id-3/file-3/content';
    const oldKeyPage2 = 'sync/inflight/sync-id-4/file-4/content';
    mockRawListObjects
      .mockResolvedValueOnce({
        Contents: [{ Key: oldKeyPage1, LastModified: new Date(now - (8 * DAY_MS)) }],
        IsTruncated: true,
        NextContinuationToken: 'token-1',
      })
      .mockResolvedValueOnce({
        Contents: [{ Key: oldKeyPage2, LastModified: new Date(now - (8 * DAY_MS)) }],
        IsTruncated: false,
      });
    const handler = await loadHandler();

    await handler();

    expect(mockRawListObjects).toHaveBeenNthCalledWith(2, 'sync/inflight/', true, 'token-1');
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith(oldKeyPage1);
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith(oldKeyPage2);
  });

  it('keeps sweeping when one deletion fails and logs a warning without the storage key', async () => {
    mockConf({ isReferenceModeEnabled: true });
    const now = Date.now();
    const failingKey = 'sync/inflight/sync-id-5/file-5/content';
    const succeedingKey = 'sync/inflight/sync-id-6/file-6/content';
    mockRawListObjects.mockResolvedValue({
      Contents: [
        { Key: failingKey, LastModified: new Date(now - (8 * DAY_MS)) },
        { Key: succeedingKey, LastModified: new Date(now - (8 * DAY_MS)) },
      ],
      IsTruncated: false,
    });
    mockDeleteFileFromStorage.mockImplementation(async (key: string) => {
      if (key === failingKey) {
        throw new Error(`Access Denied for Key: ${key}`);
      }
    });
    const handler = await loadHandler();

    await handler();

    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith(succeedingKey);
    expect(mockLogWarn).toHaveBeenCalledTimes(1);
    expect(serializeLogMeta(mockLogWarn.mock.calls[0][1])).not.toContain(failingKey);
  });
});
