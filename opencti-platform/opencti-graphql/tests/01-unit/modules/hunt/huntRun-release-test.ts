import { afterEach, describe, expect, it, vi } from 'vitest';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { patchAttribute } from '../../../../src/database/middleware';
import { deleteWork } from '../../../../src/domain/work';
import { withHuntLock } from '../../../../src/modules/hunt/hunt-lock';
import { releaseUnpublishedHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/domain/work', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/domain/work')>(),
  deleteWork: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-lock', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-lock')>(),
  withHuntLock: vi.fn(),
}));

const BEFORE = '2026-10-05T05:00:00.000Z';
const listed = { internal_id: 'run-1', work_id: 'work-1' } as BasicStoreEntityHuntRun;
const stale = { internal_id: 'run-1', hunt_run_status: 'queued', dispatched_at: '2026-10-05T04:50:00.000Z', published_at: null, work_id: 'work-1' };

describe('Release of an unpublished hunt run reservation', () => {
  afterEach(() => {
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(patchAttribute).mockReset();
    vi.mocked(deleteWork).mockReset();
    vi.mocked(withHuntLock).mockReset();
  });

  const release = async (current: Record<string, unknown>) => {
    vi.mocked(withHuntLock).mockImplementation(async (_key, action) => action());
    vi.mocked(storeLoadById).mockResolvedValue(current as never);
    vi.mocked(deleteWork).mockResolvedValue(undefined as never);
    vi.mocked(patchAttribute).mockResolvedValue({} as never);
    return releaseUnpublishedHuntRun(testContext, listed, BEFORE);
  };

  it('should release a run still queued, unpublished and holding the same work, under the transition lock of the run', async () => {
    expect(await release(stale)).toBe(true);
    expect(vi.mocked(withHuntLock).mock.calls[0][0]).toEqual('hunt_run_transition_run-1');
    // The work stays: a message published before its date could be recorded still reports to it
    expect(deleteWork).not.toHaveBeenCalled();
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).toEqual({ dispatched_at: null });
  });

  it.each([
    ['reported by its connector meanwhile', { ...stale, hunt_run_status: 'running' }],
    ['published meanwhile', { ...stale, published_at: '2026-10-05T04:51:00.000Z' }],
    ['reserved again after the listing', { ...stale, dispatched_at: '2026-10-05T05:01:00.000Z' }],
    ['holding another work', { ...stale, work_id: 'work-2' }],
  ])('should leave a run %s as it is', async (_case, current) => {
    expect(await release(current)).toBe(false);
    expect(deleteWork).not.toHaveBeenCalled();
    expect(patchAttribute).not.toHaveBeenCalled();
  });
});
