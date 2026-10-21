import { afterEach, describe, expect, it, vi } from 'vitest';
import { topEntitiesList } from '../../../../src/database/middleware-loader';
import { requeueUnpublishedHuntRuns } from '../../../../src/modules/hunt/hunt-automation';
import { releaseUnpublishedHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  topEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/huntRun/huntRun-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/huntRun/huntRun-domain')>(),
  releaseUnpublishedHuntRun: vi.fn(),
}));

describe('Hunt runs reserved and never published', () => {
  afterEach(() => {
    vi.mocked(topEntitiesList).mockReset();
    vi.mocked(releaseUnpublishedHuntRun).mockReset();
  });

  it('should release, under the run lock, each queued run reserved before the grace and never published', async () => {
    const listed = [{ internal_id: 'run-stale', work_id: 'work-1' }, { internal_id: 'run-reported-meanwhile' }] as BasicStoreEntityHuntRun[];
    vi.mocked(topEntitiesList).mockResolvedValue(listed as never);
    vi.mocked(releaseUnpublishedHuntRun).mockImplementation(async (_context, run) => run.internal_id === 'run-stale');
    expect(await requeueUnpublishedHuntRuns(testContext)).toEqual(1);
    const filters = vi.mocked(topEntitiesList).mock.calls[0][3]?.filters?.filters ?? [];
    expect(filters.find((filter) => filter.key.includes('hunt_run_status'))?.values).toEqual(['queued']);
    const reserved = filters.find((filter) => filter.key.includes('dispatched_at'));
    expect(reserved?.operator).toEqual('lte');
    expect(filters.find((filter) => filter.key.includes('published_at'))?.operator).toEqual('nil');
    // Each listed run is read again under its lock, with the same reservation threshold as the listing
    expect(vi.mocked(releaseUnpublishedHuntRun).mock.calls.map(([, run, before]) => [run.internal_id, before])).toEqual([
      ['run-stale', reserved?.values[0]],
      ['run-reported-meanwhile', reserved?.values[0]],
    ]);
  });
});
