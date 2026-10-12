import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { revertAppliedPatch } from '../../../../src/modules/curation/curation-apply';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { deleteElementById } from '../../../../src/database/middleware';
import { lockResources } from '../../../../src/lock/master-lock';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  deleteElementById: vi.fn(),
}));
vi.mock('../../../../src/lock/master-lock', () => ({
  lockResources: vi.fn(async () => ({ unlock: vi.fn() })),
}));

const context = {} as AuthContext;
const analyst = { id: 'analyst-id' } as unknown as AuthUser;
const createdAt = '2026-10-01T10:00:00.000Z';
const note = (updatedAt: string) => ({ internal_id: 'note-1', standard_id: 'note--1', entity_type: 'Note', updated_at: updatedAt });
const notePatch = { operations: [], created_ids: ['note-1'], created_versions: { 'note-1': createdAt }, applied_at: createdAt };

describe('reverting the note a proposal created', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('deletes the note while it is at the version its acceptance created, under the locks of its other identifiers', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue([note(createdAt)] as never);
    const report = await revertAppliedPatch(context, analyst, notePatch);
    expect(deleteElementById).toHaveBeenCalledWith(context, analyst, 'note-1', 'Note');
    expect(report.reverted_operations).toBe(1);
    const lockIds = vi.mocked(lockResources).mock.calls[0][0] as string[];
    expect(lockIds).toContain('note--1');
    expect(lockIds).not.toContain('note-1');
  });

  it('keeps a note modified since, read again under the lock, and reports it', async () => {
    vi.mocked(internalFindByIds)
      .mockResolvedValueOnce([note(createdAt)] as never)
      .mockResolvedValueOnce([note('2026-10-02T09:00:00.000Z')] as never);
    const report = await revertAppliedPatch(context, analyst, notePatch);
    expect(deleteElementById).not.toHaveBeenCalled();
    expect(report.reverted_operations).toBe(0);
    expect(report.skipped_operations).toEqual([{ element_id: 'note-1', key: 'Note', reason: 'changed since the apply' }]);
    const lock = await vi.mocked(lockResources).mock.results[0].value;
    expect(lock.unlock).toHaveBeenCalled();
  });
});
