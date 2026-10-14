import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockRawListObjects = vi.fn();
const mockDeleteFileFromStorage = vi.fn();
const mockRegisterManager = vi.fn();
const DAY_MS = 24 * 60 * 60 * 1000;

vi.mock('../../../src/manager/managerModule', () => ({
  registerManager: (...args: unknown[]) => mockRegisterManager(...args),
}));
vi.mock('../../../src/database/raw-file-storage', () => ({
  rawListObjects: (...args: unknown[]) => mockRawListObjects(...args),
  deleteFileFromStorage: (...args: unknown[]) => mockDeleteFileFromStorage(...args),
}));
vi.mock('../../../src/modules/internal/document/document-types', () => ({
  SYNC_INFLIGHT_STORAGE_PATH: 'sync/inflight',
}));

let syncInflightCleanupHandler: () => Promise<void>;

describe('sync inflight cleanup manager (f3 - TTL backstop)', () => {
  beforeEach(async () => {
    vi.resetModules();
    mockRawListObjects.mockReset();
    mockDeleteFileFromStorage.mockReset();
    mockRegisterManager.mockReset();
    ({ syncInflightCleanupHandler } = await import('../../../src/manager/syncInflightCleanupManager'));
  });

  it('deletes only sync/inflight keys older than the TTL, leaving recent in-flight transfers untouched', async () => {
    const now = Date.now();
    const oldKey = 'sync/inflight/sync-id-1/file-1/content';
    const recentKey = 'sync/inflight/sync-id-2/file-2/content';
    mockRawListObjects.mockResolvedValue({
      Contents: [
        { Key: oldKey, LastModified: new Date(now - (8 * DAY_MS)) },
        { Key: recentKey, LastModified: new Date(now - (60 * 1000)) }, // 1 minute old
      ],
      IsTruncated: false,
    });

    await syncInflightCleanupHandler();

    expect(mockRawListObjects).toHaveBeenCalledWith('sync/inflight/', true, undefined);
    expect(mockDeleteFileFromStorage).toHaveBeenCalledTimes(1);
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith(oldKey);
  });

  it('keeps a staged file younger than the default TTL of one week, so a slow worker backlog can still consume it', async () => {
    const backloggedKey = 'sync/inflight/sync-id-7/file-7/content';
    mockRawListObjects.mockResolvedValue({
      Contents: [{ Key: backloggedKey, LastModified: new Date(Date.now() - (6 * DAY_MS)) }],
      IsTruncated: false,
    });

    await syncInflightCleanupHandler();

    expect(mockDeleteFileFromStorage).not.toHaveBeenCalled();
  });

  it('stays enabled with the sync manager after file reference mode is turned off, so earlier staged files are still cleaned', async () => {
    vi.resetModules();
    vi.doMock('../../../src/config/conf', async (importOriginal) => {
      const actual = await importOriginal() as Record<string, unknown>;
      return { ...actual, ENABLED_SYNC_MANAGER: true, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE: false };
    });
    await import('../../../src/manager/syncInflightCleanupManager');
    vi.doUnmock('../../../src/config/conf');

    expect(mockRegisterManager).toHaveBeenCalledWith(expect.objectContaining({ id: 'SYNC_INFLIGHT_CLEANUP_MANAGER', enabledByConfig: true }));
  });

  it('does nothing when sync/inflight is empty (the expected steady state, since the happy path self-cleans)', async () => {
    mockRawListObjects.mockResolvedValue({ Contents: [], IsTruncated: false });

    await syncInflightCleanupHandler();

    expect(mockDeleteFileFromStorage).not.toHaveBeenCalled();
  });

  it('paginates through multiple S3 listing pages using the continuation token', async () => {
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

    await syncInflightCleanupHandler();

    expect(mockRawListObjects).toHaveBeenCalledTimes(2);
    expect(mockRawListObjects).toHaveBeenNthCalledWith(2, 'sync/inflight/', true, 'token-1');
    expect(mockDeleteFileFromStorage).toHaveBeenCalledTimes(2);
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith(oldKeyPage1);
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith(oldKeyPage2);
  });

  it('continues sweeping other keys when one deletion fails, without throwing', async () => {
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
        throw new Error('S3 unavailable');
      }
    });

    await expect(syncInflightCleanupHandler()).resolves.not.toThrow();
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith(failingKey);
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith(succeedingKey);
  });
});
