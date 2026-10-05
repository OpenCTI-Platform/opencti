import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { settlePendingMergeRecord } from '../../../../src/modules/curation/curation-merge-record';
import { deleteElementById, patchAttribute, storeLoadByIdWithRefs } from '../../../../src/database/middleware';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { assertedAuthorityKeys } from '../../../../src/utils/upsert-utils';
import type { BasicStoreEntityMergeRecord } from '../../../../src/modules/curation/curation-types';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  deleteElementById: vi.fn(),
  patchAttribute: vi.fn(async () => ({ element: {} })),
  storeLoadByIdWithRefs: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(),
}));
vi.mock('../../../../src/manager/telemetryManager', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/manager/telemetryManager')>()),
  addCurationMergeRecordCount: vi.fn(),
}));

const context = {} as AuthContext;
const target = { internal_id: 'target-id', standard_id: 'intrusion-set--target', entity_type: 'Intrusion-Set', name: 'Cl0p' };
const record = (overrides: Partial<BasicStoreEntityMergeRecord> = {}) => ({
  internal_id: 'record-id',
  merge_status: 'pending',
  merge_target_id: 'target-id',
  merge_source_ids: ['source-id'],
  merge_snapshot: { target: { attributes: {}, refs: {} }, sources: [{ internal_id: 'source-id', name: 'TA505', moved_file_ids: [] }] },
  ...overrides,
} as unknown as BasicStoreEntityMergeRecord);

describe('pending merge records settled from the live graph', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('discards the record of a merge that never started, so the merge runs again', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce({ 'source-id': { internal_id: 'source-id' } } as never);
    expect(await settlePendingMergeRecord(context, record())).toBe('discarded');
    expect(deleteElementById).toHaveBeenCalledWith(context, expect.anything(), 'record-id', 'MergeRecord');
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('completes the record of a merge whose sources are gone', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce({} as never);
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValueOnce(target as never);
    expect(await settlePendingMergeRecord(context, record({ merge_started_at: '2026-10-05T07:00:00.000Z' } as never))).toBe('completed');
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).toMatchObject({ merge_status: 'active' });
  });

  it('keeps as irreversible a merge that started writing and left a source behind', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce({ 'source-id': { internal_id: 'source-id' } } as never);
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValueOnce(target as never);
    expect(await settlePendingMergeRecord(context, record({ merge_started_at: '2026-10-05T07:00:00.000Z' } as never))).toBe('irreversible');
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).toEqual({ merge_status: 'irreversible', irreversible_reason: 'merge_interrupted' });
  });
});

describe('field authority bookkeeping of an upsert', () => {
  it('records the governed fields a more authoritative source asserted with their current value', () => {
    const decisions = new Map([['description', 'allow'], ['name', 'allow'], ['aliases', 'deny']]);
    const patch = { description: 'Same text', name: 'New name', aliases: ['FIN11'], first_seen: '2026-01-01T00:00:00.000Z' };
    const element = { description: 'Same text', name: 'Old name', aliases: ['FIN11'] };
    expect(assertedAuthorityKeys(decisions, patch, element)).toEqual(['description']);
    expect(assertedAuthorityKeys(new Map([['description', 'allow']]), { description: '' }, { description: '' })).toEqual([]);
    expect(assertedAuthorityKeys(undefined, patch, element)).toEqual([]);
  });
});
