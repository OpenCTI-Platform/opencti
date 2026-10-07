import { beforeEach, describe, expect, it, vi } from 'vitest';
import { moveFilesBack } from '../../../../src/modules/curation/curation-merge-record';
import { copyFile, deleteFile, loadFile } from '../../../../src/database/file-storage';
import { patchAttribute } from '../../../../src/database/middleware';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { StoreObject } from '../../../../src/types/store';

vi.mock('../../../../src/database/file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/file-storage')>()),
  loadFile: vi.fn(),
  copyFile: vi.fn(),
  deleteFile: vi.fn(async () => undefined),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  patchAttribute: vi.fn(async () => ({ element: {} })),
}));

const context = {} as AuthContext;
const user = { id: 'analyst-id' } as AuthUser;
const FIRST = 'import/Intrusion-Set/target-id/first.pdf';
const SECOND = 'import/Intrusion-Set/target-id/second.pdf';
const OWN = 'import/Intrusion-Set/target-id/own.pdf';
const restoredPath = (id: string) => id.replace('/target-id/', '/source-id/');
const target = {
  internal_id: 'target-id',
  entity_type: 'Intrusion-Set',
  x_opencti_files: [FIRST, SECOND, OWN].map((id) => ({ id, name: id.split('/').pop() })),
} as unknown as StoreObject;
const restored = { internal_id: 'source-id', entity_type: 'Intrusion-Set', x_opencti_files: [] } as unknown as StoreObject;
const document = (id: string) => ({ id, name: id.split('/').pop(), size: 1, metaData: { version: '1', mimetype: 'application/pdf' } });

const filesPatchedOn = (entityId: string) => {
  const call = vi.mocked(patchAttribute).mock.calls.find((args) => args[2] === entityId);
  return ((call?.[4] as { x_opencti_files: Array<{ id: string }> }).x_opencti_files).map((file) => file.id);
};

describe('curation unmerge of the merged files', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(loadFile).mockImplementation(async (_context, _user, id: string) => (id.includes('/target-id/') ? document(id) : null) as never);
    vi.mocked(copyFile).mockImplementation(async (_context, { targetId }) => document(targetId) as never);
  });

  it('moves every merged file back to the restored entity', async () => {
    await moveFilesBack(context, user, target, restored, [FIRST, SECOND], ['lock-id']);
    expect(deleteFile).toHaveBeenCalledTimes(2);
    expect(filesPatchedOn('source-id')).toEqual([restoredPath(FIRST), restoredPath(SECOND)]);
    expect(filesPatchedOn('target-id')).toEqual([OWN]);
  });

  it('stops the unmerge on a file it cannot copy back, once the files already moved are recorded', async () => {
    vi.mocked(copyFile)
      .mockImplementationOnce(async (_context, { targetId }) => document(targetId) as never)
      .mockResolvedValueOnce(null);
    await expect(moveFilesBack(context, user, target, restored, [FIRST, SECOND], ['lock-id']))
      .rejects.toThrow('A merged file cannot be moved back to the restored entity');
    expect(deleteFile).toHaveBeenCalledTimes(1);
    expect(deleteFile).toHaveBeenCalledWith(context, expect.anything(), FIRST);
    expect(filesPatchedOn('source-id')).toEqual([restoredPath(FIRST)]);
    expect(filesPatchedOn('target-id')).toEqual([SECOND, OWN]);
  });

  it('resumes with the files the stopped unmerge moved, and copies the one that failed again', async () => {
    const stoppedTarget = { ...target, x_opencti_files: target.x_opencti_files?.filter((file) => file.id !== FIRST) } as StoreObject;
    vi.mocked(loadFile).mockImplementation(async (_context, _user, id: string) => (id === FIRST ? null : document(id)) as never);
    await moveFilesBack(context, user, stoppedTarget, restored, [FIRST, SECOND], ['lock-id']);
    expect(copyFile).toHaveBeenCalledTimes(1);
    expect(copyFile).toHaveBeenCalledWith(context, expect.objectContaining({ sourceId: SECOND, targetId: restoredPath(SECOND) }));
    expect(filesPatchedOn('source-id')).toEqual([restoredPath(FIRST), restoredPath(SECOND)]);
    expect(filesPatchedOn('target-id')).toEqual([OWN]);
  });
});
