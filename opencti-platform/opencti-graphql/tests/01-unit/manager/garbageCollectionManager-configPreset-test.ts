import { beforeEach, describe, expect, it, vi } from 'vitest';

const flags = vi.hoisted(() => ({ enabled: true }));
vi.mock('../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn(() => flags.enabled),
}));
vi.mock('../../../src/modules/deleteOperation/deleteOperation-domain', () => ({
  findOldDeleteOperations: vi.fn().mockResolvedValue([]),
  confirmDelete: vi.fn(),
}));
vi.mock('../../../src/database/redis-stream', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis-stream')>()),
  rawFetchStreamInfo: vi.fn().mockResolvedValue({ firstEventId: '0-0' }),
}));
vi.mock('../../../src/database/file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/file-storage')>()),
  loadedFilesListing: vi.fn().mockResolvedValue({ KeyCount: 0 }),
}));
vi.mock('../../../src/modules/configPreset/import/configPreset-import-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/configPreset/import/configPreset-import-domain')>()),
  deleteExpiredConfigPresetImportFiles: vi.fn(),
}));
vi.mock('../../../src/modules/configPreset/export/configPreset-export-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/configPreset/export/configPreset-export-domain')>()),
  deleteExpiredConfigPresetExports: vi.fn(),
}));

import { garbageCollectionHandler } from '../../../src/manager/garbageCollectionManager';
import { deleteExpiredConfigPresetExports } from '../../../src/modules/configPreset/export/configPreset-export-domain';
import { deleteExpiredConfigPresetImportFiles } from '../../../src/modules/configPreset/import/configPreset-import-domain';
import { GARBAGE_COLLECTION_MANAGER_USER } from '../../../src/utils/access';

describe('Garbage collection manager - configuration preset files', () => {
  beforeEach(() => {
    flags.enabled = true;
    vi.mocked(deleteExpiredConfigPresetExports).mockClear();
    vi.mocked(deleteExpiredConfigPresetImportFiles).mockClear();
  });

  it('removes the expired configuration preset exports at each run, as the garbage collection user', async () => {
    await garbageCollectionHandler();
    expect(deleteExpiredConfigPresetExports).toHaveBeenCalledTimes(1);
    expect(deleteExpiredConfigPresetExports).toHaveBeenCalledWith(expect.anything(), GARBAGE_COLLECTION_MANAGER_USER);
    await garbageCollectionHandler();
    expect(deleteExpiredConfigPresetExports).toHaveBeenCalledTimes(2);
  });

  it('removes the expired uploads and history of the configuration preset imports at each run, as the garbage collection user', async () => {
    await garbageCollectionHandler();
    expect(deleteExpiredConfigPresetImportFiles).toHaveBeenCalledTimes(1);
    expect(deleteExpiredConfigPresetImportFiles).toHaveBeenCalledWith(expect.anything(), GARBAGE_COLLECTION_MANAGER_USER);
  });

  it('does not look for configuration preset files when CONFIG_PRESET is disabled', async () => {
    flags.enabled = false;
    await garbageCollectionHandler();
    expect(deleteExpiredConfigPresetExports).not.toHaveBeenCalled();
    expect(deleteExpiredConfigPresetImportFiles).not.toHaveBeenCalled();
  });
});
