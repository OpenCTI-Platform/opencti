import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/file-storage')>()),
  deleteFile: vi.fn(),
}));
vi.mock('../../../../src/modules/internal/document/document-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/internal/document/document-domain')>()),
  allFilesForPaths: vi.fn(),
}));

import { deleteFile } from '../../../../src/database/file-storage';
import { allFilesForPaths } from '../../../../src/modules/internal/document/document-domain';
import { deleteExpiredConfigPresetExports } from '../../../../src/modules/configPreset/configPreset-domain';
import { GARBAGE_COLLECTION_MANAGER_USER } from '../../../../src/utils/access';
import type { AuthContext } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const NOW = new Date('2026-10-14T09:05:07.123Z');

describe('Config preset expired exports cleanup', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
    vi.mocked(allFilesForPaths).mockResolvedValue([]);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('deletes the exports older than one hour, in every export folder', async () => {
    vi.mocked(allFilesForPaths).mockResolvedValue([{ id: 'config_preset/old-folder/old.zip' }] as never);
    await deleteExpiredConfigPresetExports(context, GARBAGE_COLLECTION_MANAGER_USER);
    expect(allFilesForPaths).toHaveBeenCalledWith(context, GARBAGE_COLLECTION_MANAGER_USER, ['config_preset/export'], { notModifiedSince: '2026-10-14T08:05:07.123Z' });
    expect(deleteFile).toHaveBeenCalledWith(context, GARBAGE_COLLECTION_MANAGER_USER, 'config_preset/old-folder/old.zip');
  });

  it('keeps deleting the other expired exports when one deletion fails', async () => {
    vi.mocked(allFilesForPaths).mockResolvedValue([
      { id: 'config_preset/a/old.zip' },
      { id: 'config_preset/b/old.zip' },
      { id: 'config_preset/c/old.zip' },
    ] as never);
    vi.mocked(deleteFile).mockImplementation(async (_ctx, _user, id) => {
      if (id === 'config_preset/b/old.zip') {
        throw new Error('storage down');
      }
      return undefined;
    });
    await deleteExpiredConfigPresetExports(context, GARBAGE_COLLECTION_MANAGER_USER);
    expect(vi.mocked(deleteFile).mock.calls.map(([, , id]) => id)).toEqual(['config_preset/a/old.zip', 'config_preset/b/old.zip', 'config_preset/c/old.zip']);
  });

  it('does not throw when the expired exports cannot be listed', async () => {
    vi.mocked(allFilesForPaths).mockRejectedValue(new Error('index down'));
    await expect(deleteExpiredConfigPresetExports(context, GARBAGE_COLLECTION_MANAGER_USER)).resolves.toBeUndefined();
    expect(deleteFile).not.toHaveBeenCalled();
  });
});
