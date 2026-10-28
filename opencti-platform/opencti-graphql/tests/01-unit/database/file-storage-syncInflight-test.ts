import { beforeEach, describe, expect, it, vi } from 'vitest';

// The stored document of a file is read through storeLoadById
vi.mock('../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));

import { storeLoadById } from '../../../src/database/middleware-loader';
import { loadFile } from '../../../src/database/file-storage';
import { SYNC_INFLIGHT_STORAGE_PATH } from '../../../src/modules/internal/document/document-types';
import { SYSTEM_USER } from '../../../src/utils/access';
import type { AuthContext } from '../../../src/types/user';

const context = { source: 'test' } as AuthContext;

const RESTRICTED = 'File not found or restricted';
const stagedFileId = `${SYNC_INFLIGHT_STORAGE_PATH}/sync-id/0f1e2d3c4b5a69788796a5b4c3d2e1f0/content`;
const draftStagedFileId = `draft/draft-id/${stagedFileId}`;
const lookalikeFileId = `${SYNC_INFLIGHT_STORAGE_PATH}X/sync-id/0f1e2d3c4b5a69788796a5b4c3d2e1f0/content`;
const storedFileIds = [stagedFileId, draftStagedFileId, lookalikeFileId];

describe('loadFile on staged sync files', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(storeLoadById).mockImplementation(async (_ctx, _user, id) => {
      const storedId = storedFileIds.find((fileId) => fileId === id);
      return (storedId ? { id: storedId, internal_id: storedId, metaData: {} } : undefined) as never;
    });
  });

  it('refuses a staged key to every user, system included', async () => {
    await expect(loadFile(context, SYSTEM_USER, stagedFileId)).rejects.toThrow(RESTRICTED);
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('refuses the draft copy of a staged key', async () => {
    await expect(loadFile(context, SYSTEM_USER, draftStagedFileId)).rejects.toThrow(RESTRICTED);
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('returns undefined instead of throwing with dontThrow', async () => {
    await expect(loadFile(context, SYSTEM_USER, stagedFileId, { dontThrow: true })).resolves.toBeUndefined();
    await expect(loadFile(context, SYSTEM_USER, draftStagedFileId, { dontThrow: true })).resolves.toBeUndefined();
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('does not match a sibling root that only shares the prefix', async () => {
    const file = await loadFile(context, SYSTEM_USER, lookalikeFileId);
    expect(file?.id).toBe(lookalikeFileId);
  });
});
