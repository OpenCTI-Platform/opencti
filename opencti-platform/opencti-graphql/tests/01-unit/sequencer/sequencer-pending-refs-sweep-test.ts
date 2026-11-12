import { describe, expect, it, vi } from 'vitest';
import {
  buildPendingRecords,
  pendingRefsCount,
  persistPendingRecords,
  registerPendingRefsEsOps,
  registerReconcileAssert,
  sweepPendingRefsOnce,
} from '../../../src/database/sequencer/sequencer-pending-refs';

// task 0040 (multi-writer diag 2026-11-12): the sweeper re-asserted its records one at a time
// through the loop, each record whose target never comes waiting for the park deadline; the
// records whose target had landed waited behind them. It now searches the targets once and
// re-asserts only the records whose target exists.

const strip = (ownerId: string, targetRef: string) => ({ ownerId, ownerType: 'Report', relType: 'object', targetRef, userId: 'u1' });

describe('pending refs sweeper', () => {
  it('should re-assert only the records whose target exists and count the others as attempts', async () => {
    const bulk = vi.fn().mockResolvedValue({ errors: false, items: [] });
    const findExisting = vi.fn().mockResolvedValue(new Set(['relationship--landed']));
    registerPendingRefsEsOps({ indexExists: vi.fn(), createIndex: vi.fn(), bulk, search: vi.fn(), findExisting });
    const reconcile = vi.fn().mockResolvedValue(undefined);
    registerReconcileAssert(reconcile);
    const records = buildPendingRecords([strip('report-1', 'relationship--landed'), strip('report-2', 'identity--never'), strip('report-3', 'identity--never')]);
    records.forEach((record) => {
      record.created_at = Date.now() - 60_000; // aged past the sweep threshold
    });
    await persistPendingRecords(records);
    bulk.mockClear();

    await sweepPendingRefsOnce();

    expect(findExisting).toHaveBeenCalledTimes(1);
    expect(findExisting.mock.calls[0][0].sort()).toEqual(['identity--never', 'relationship--landed']);
    expect(reconcile).toHaveBeenCalledTimes(1);
    expect(reconcile.mock.calls[0][0].owner_id).toEqual('report-1');
    expect(pendingRefsCount()).toBe(2);
    // the two records without target: one bulk of attempt updates, no re-assertion
    const bumped = bulk.mock.calls.flatMap(([body]) => body).filter((line: any) => line.update).map((line: any) => line.update._id);
    expect(bumped).toEqual(expect.arrayContaining(records.slice(1).map((r) => r.id)));
    expect(records[1].attempts).toBe(1);
  });
});
