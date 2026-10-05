import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { revertAppliedPatch } from '../../../../src/modules/curation/curation-apply';
import { fullEntitiesList, storeLoadById } from '../../../../src/database/middleware-loader';
import { restoreDelete } from '../../../../src/modules/deleteOperation/deleteOperation-domain';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/modules/deleteOperation/deleteOperation-domain', () => ({ restoreDelete: vi.fn() }));

const context = {} as AuthContext;
const analyst = { id: 'analyst-id' } as unknown as AuthUser;
const appliedAt = '2026-10-01T10:00:00.000Z';

describe('reverting the attributions a proposal removed', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('restores the deletion the apply recorded, never a later one', async () => {
    vi.mocked(storeLoadById).mockResolvedValue({ internal_id: 'operation-of-the-apply' } as never);
    const report = await revertAppliedPatch(context, analyst, {
      operations: [],
      deleted_ids: ['attribution-b'],
      delete_operation_ids: { 'attribution-b': 'operation-of-the-apply' },
      applied_at: appliedAt,
    });
    expect(restoreDelete).toHaveBeenCalledWith(context, analyst, 'operation-of-the-apply');
    expect(fullEntitiesList).not.toHaveBeenCalled();
    expect(report.reverted_operations).toBe(1);
  });

  it('skips a deletion already restored, even when the relationship was deleted again since', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(undefined as never);
    const report = await revertAppliedPatch(context, analyst, {
      operations: [],
      deleted_ids: ['attribution-b'],
      delete_operation_ids: { 'attribution-b': 'operation-of-the-apply' },
      applied_at: appliedAt,
    });
    expect(restoreDelete).not.toHaveBeenCalled();
    expect(report.skipped_operations).toEqual([{ element_id: 'attribution-b', key: 'relationship', reason: 'not found in the trash anymore' }]);
  });

  it('without a recorded operation, only looks at deletions made by the time of the apply', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([{ internal_id: 'operation-of-the-apply' }] as never);
    await revertAppliedPatch(context, analyst, { operations: [], deleted_ids: ['attribution-b'], applied_at: appliedAt });
    const filters = (vi.mocked(fullEntitiesList).mock.calls[0][3] as any).filters.filters;
    expect(filters).toContainEqual({ key: ['created_at'], values: [appliedAt], operator: 'lte' });
    expect(restoreDelete).toHaveBeenCalledWith(context, analyst, 'operation-of-the-apply');
  });
});
