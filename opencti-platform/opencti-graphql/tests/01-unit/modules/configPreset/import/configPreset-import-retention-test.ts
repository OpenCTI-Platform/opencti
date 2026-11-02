import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/internal/document/document-domain', () => ({ allFilesForPaths: vi.fn() }));
vi.mock('../../../../../src/database/file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/database/file-storage')>()),
  deleteFile: vi.fn(),
}));

import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import {
  CONFIG_PRESET_IMPORT_HISTORY_RETENTION_MS,
  CONFIG_PRESET_IMPORT_UPLOAD_RETENTION_MS,
  deleteExpiredConfigPresetImportFiles,
} from '../../../../../src/modules/configPreset/import/configPreset-import-domain';
import { CONFIG_PRESET_HISTORY_PATH, CONFIG_PRESET_IMPORT_PATH } from '../../../../../src/modules/internal/document/document-types';
import { GARBAGE_COLLECTION_MANAGER_USER } from '../../../../../src/utils/access';
import type { AuthContext } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const NOW = new Date('2026-10-29T12:00:00.000Z');

describe('Config preset import retention', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.useFakeTimers({ now: NOW });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const listedFor = (path: string) => vi.mocked(allFilesForPaths).mock.calls.find(([, , paths]) => paths[0] === path);

  it('keeps an upload that was never imported for a day, and the history for thirty days', async () => {
    vi.mocked(allFilesForPaths).mockResolvedValue([]);
    await deleteExpiredConfigPresetImportFiles(context, GARBAGE_COLLECTION_MANAGER_USER);
    expect(listedFor(CONFIG_PRESET_IMPORT_PATH)?.[3]).toEqual({ notModifiedSince: new Date(NOW.getTime() - CONFIG_PRESET_IMPORT_UPLOAD_RETENTION_MS).toISOString() });
    expect(listedFor(CONFIG_PRESET_HISTORY_PATH)?.[3]).toEqual({ notModifiedSince: new Date(NOW.getTime() - CONFIG_PRESET_IMPORT_HISTORY_RETENTION_MS).toISOString() });
    expect(CONFIG_PRESET_IMPORT_UPLOAD_RETENTION_MS).toEqual(24 * 60 * 60 * 1000);
    expect(CONFIG_PRESET_IMPORT_HISTORY_RETENTION_MS).toEqual(30 * 24 * 60 * 60 * 1000);
  });

  it('deletes the expired files of both folders, and goes on when one cannot be deleted', async () => {
    vi.mocked(allFilesForPaths).mockImplementation((async (_context: unknown, _user: unknown, paths: string[]) => (
      paths[0] === CONFIG_PRESET_IMPORT_PATH ? [{ id: 'import/a.zip' }, { id: 'import/b.zip' }] : [{ id: 'history/c.json' }]
    )) as never);
    vi.mocked(deleteFile).mockRejectedValueOnce(new Error('storage down'));
    await deleteExpiredConfigPresetImportFiles(context, GARBAGE_COLLECTION_MANAGER_USER);
    expect(vi.mocked(deleteFile).mock.calls.map(([, , id]) => id)).toEqual(['import/a.zip', 'import/b.zip', 'history/c.json']);
    expect(vi.mocked(deleteFile).mock.calls.every(([, , , options]) => options?.forceDelete === true)).toBe(true);
  });

  it('cleans the history even when the uploads cannot be listed', async () => {
    vi.mocked(allFilesForPaths).mockImplementation((async (_context: unknown, _user: unknown, paths: string[]) => {
      if (paths[0] === CONFIG_PRESET_IMPORT_PATH) {
        throw new Error('elastic down');
      }
      return [{ id: 'history/c.json' }];
    }) as never);
    await deleteExpiredConfigPresetImportFiles(context, GARBAGE_COLLECTION_MANAGER_USER);
    expect(vi.mocked(deleteFile).mock.calls.map(([, , id]) => id)).toEqual(['history/c.json']);
  });
});
