import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { completePendingMergeRecords, expireMergeRecords, settlePendingMergeRecord } from '../../../../src/modules/curation/curation-merge-record';
import { deleteElementById, patchAttribute, storeLoadByIdWithRefs } from '../../../../src/database/middleware';
import { internalFindByIds, pageEntitiesConnection } from '../../../../src/database/middleware-loader';
import { lockResources } from '../../../../src/lock/master-lock';
import { assertedAuthorityKeys } from '../../../../src/utils/upsert-utils';
import type { BasicStoreEntityMergeRecord } from '../../../../src/modules/curation/curation-types';
import type { AuthContext } from '../../../../src/types/user';

const unlock = vi.fn();
let stored: BasicStoreEntityMergeRecord | undefined;

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  deleteElementById: vi.fn(),
  patchAttribute: vi.fn(async () => ({ element: {} })),
  storeLoadByIdWithRefs: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(async () => stored),
}));
vi.mock('../../../../src/lock/master-lock', () => ({ lockResources: vi.fn(async () => ({ unlock })) }));
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
const storedRecord = (overrides: Partial<BasicStoreEntityMergeRecord> = {}) => {
  stored = record(overrides);
  return stored;
};
const lockBusy = () => Object.assign(new Error('busy'), { name: 'ExecutionError' });
const pageOf = (records: BasicStoreEntityMergeRecord[]) => ({ edges: records.map((node) => ({ node })), pageInfo: { hasNextPage: false } });

describe('pending merge records settled from the live graph', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    stored = undefined;
  });

  it('discards the record of a merge that never started, so the merge runs again', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce({ 'source-id': { internal_id: 'source-id' } } as never);
    expect(await settlePendingMergeRecord(context, storedRecord())).toBe('discarded');
    expect(deleteElementById).toHaveBeenCalledWith(context, expect.anything(), 'record-id', 'MergeRecord');
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('settles a record under the locks its merge holds on the participants, and frees them', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce({ 'source-id': { internal_id: 'source-id' } } as never);
    await settlePendingMergeRecord(context, storedRecord());
    expect(lockResources).toHaveBeenCalledWith(['target-id', 'source-id'], { restoredIds: ['source-id'] });
    expect(unlock).toHaveBeenCalledTimes(1);
  });

  it('leaves as it is a record its merge settled once the participants are locked', async () => {
    const pending = record();
    storedRecord({ merge_status: 'active', merge_started_at: '2026-10-05T07:00:00.000Z' } as never);
    expect(await settlePendingMergeRecord(context, pending)).toBe('settled');
    expect(internalFindByIds).not.toHaveBeenCalled();
    expect(deleteElementById).not.toHaveBeenCalled();
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('completes the record of a merge whose sources are gone', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce({} as never);
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValueOnce(target as never);
    expect(await settlePendingMergeRecord(context, storedRecord({ merge_started_at: '2026-10-05T07:00:00.000Z' } as never))).toBe('completed');
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).toMatchObject({ merge_status: 'active' });
  });

  it('keeps as irreversible a merge that started writing and left a source behind', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce({ 'source-id': { internal_id: 'source-id' } } as never);
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValueOnce(target as never);
    expect(await settlePendingMergeRecord(context, storedRecord({ merge_started_at: '2026-10-05T07:00:00.000Z' } as never))).toBe('irreversible');
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).toEqual({ merge_status: 'irreversible', irreversible_reason: 'merge_interrupted' });
  });

  it('leaves the record of a merge still running for a later cycle, and settles the others', async () => {
    vi.mocked(pageEntitiesConnection).mockResolvedValueOnce(pageOf([record({ internal_id: 'running-id' } as never), storedRecord()]) as never);
    vi.mocked(lockResources).mockRejectedValueOnce(lockBusy());
    vi.mocked(internalFindByIds).mockResolvedValueOnce({ 'source-id': { internal_id: 'source-id' } } as never);
    expect(await completePendingMergeRecords(context)).toEqual({ completed: 0, discarded: 1, irreversible: 0 });
    expect(deleteElementById).toHaveBeenCalledTimes(1);
  });
});

describe('merge records closed after their retention window', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    stored = undefined;
  });

  const open = { merge_status: 'active', reversible_until: '2025-10-05T07:00:00.000Z' } as never;

  it('closes a record under the lock an unmerge holds on it', async () => {
    vi.mocked(pageEntitiesConnection).mockResolvedValueOnce(pageOf([storedRecord(open)]) as never);
    expect(await expireMergeRecords(context)).toBe(1);
    expect(lockResources).toHaveBeenCalledWith(['record-id']);
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).toMatchObject({ merge_status: 'irreversible', irreversible_reason: 'retention_over' });
    expect(vi.mocked(patchAttribute).mock.calls[0][5]).toEqual({ locks: ['record-id'] });
    expect(unlock).toHaveBeenCalledTimes(1);
  });

  it('leaves open a record an unmerge reverted once it is locked', async () => {
    vi.mocked(pageEntitiesConnection).mockResolvedValueOnce(pageOf([record(open)]) as never);
    storedRecord({ merge_status: 'reverted' } as never);
    expect(await expireMergeRecords(context)).toBe(0);
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('leaves a record an unmerge still holds for a later run', async () => {
    vi.mocked(pageEntitiesConnection).mockResolvedValueOnce(pageOf([storedRecord(open)]) as never);
    vi.mocked(lockResources).mockRejectedValueOnce(lockBusy());
    expect(await expireMergeRecords(context)).toBe(0);
    expect(patchAttribute).not.toHaveBeenCalled();
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
