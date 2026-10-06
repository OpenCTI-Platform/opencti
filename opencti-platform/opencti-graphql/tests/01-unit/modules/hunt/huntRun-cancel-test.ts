import { afterEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, internalFindByIds, internalLoadById, storeLoadById } from '../../../../src/database/middleware-loader';
import { cancelOrphanHuntRuns } from '../../../../src/modules/hunt/hunt-automation';
import { HUNT_CONFIG } from '../../../../src/modules/hunt/hunt-utils';
import { cursorToOffset } from '../../../../src/database/utils';
import { patchAttribute } from '../../../../src/database/middleware';
import { elAggregationCount, elHistogramCount, elHistogramSum } from '../../../../src/database/engine';
import { withHuntLock } from '../../../../src/modules/hunt/hunt-lock';
import { HUNT_MESSAGES } from '../../../../src/modules/hunt/hunt-messages';
import { cancelHuntRun, computeHuntStatistics, expireHuntRun, isHuntRunFinalized, isHuntRunHuntDeleted } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalFindByIds: vi.fn(),
  fullEntitiesList: vi.fn(),
  internalLoadById: vi.fn(),
  storeLoadById: vi.fn(),
  topEntitiesList: vi.fn(async () => []),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/engine')>(),
  elAggregationCount: vi.fn(async () => []),
  elHistogramCount: vi.fn(async () => []),
  elHistogramSum: vi.fn(async () => []),
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/redis')>(),
  notify: vi.fn(async (_topic, instance) => instance),
}));

vi.mock('../../../../src/modules/hunt/hunt-lock', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-lock')>(),
  withHuntLock: vi.fn(async (_key, action) => action()),
}));

const queued = { internal_id: 'run-1', hunt_id: 'hunt-1', hunt_run_status: 'queued', hunt_run_mode: 'execute', attempt: 1, dispatched_at: '2026-10-05T04:50:00.000Z' };

const patched = () => vi.mocked(patchAttribute).mock.calls.map((call) => call[4]);

describe('Cancellation of the runs of a deleted hunt or hunt connector', () => {
  afterEach(() => {
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(internalLoadById).mockReset();
    vi.mocked(patchAttribute).mockReset();
  });

  const loading = (current: Record<string, unknown>) => {
    vi.mocked(storeLoadById).mockResolvedValue(current as never);
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, _id, _type, patch) => ({ element: { ...current, ...patch } }) as never);
  };

  it('should cancel a queued run under its transition lock, which frees its slot and plans no retry', async () => {
    loading(queued);
    const run = await cancelHuntRun(testContext, 'run-1', HUNT_MESSAGES.runCancelledHuntDeleted);
    expect(vi.mocked(withHuntLock).mock.calls.at(-1)?.[0]).toEqual('hunt_run_transition_run-1');
    expect(patched()[0]).toMatchObject({ hunt_run_status: 'cancelled', error_message: HUNT_MESSAGES.runCancelledHuntDeleted, next_retry_at: null });
    expect(run?.hunt_run_status).toEqual('cancelled');
  });

  it('should only clear the planned retry of a terminated run, and leave any other terminated run as it is', async () => {
    loading({ ...queued, hunt_run_status: 'timeout', next_retry_at: '2026-10-05T06:00:00.000Z' });
    await cancelHuntRun(testContext, 'run-1', HUNT_MESSAGES.runCancelledConnectorDeleted);
    expect(patched()).toEqual([{ next_retry_at: null }]);
    vi.mocked(patchAttribute).mockReset();
    loading({ ...queued, hunt_run_status: 'completed', next_retry_at: null });
    expect(await cancelHuntRun(testContext, 'run-1', HUNT_MESSAGES.runCancelledConnectorDeleted)).toBeNull();
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should cancel, never time out with a verdict, a run expiring after its hunt was deleted', async () => {
    loading(queued);
    vi.mocked(internalLoadById).mockResolvedValue(undefined as never);
    const run = await expireHuntRun(testContext, queued as BasicStoreEntityHuntRun, 'No report within the run timeout');
    expect(run.hunt_run_status).toEqual('cancelled');
    expect(patched()).toHaveLength(1);
    expect(patched()[0]).not.toHaveProperty('verdict');
  });

  it('should hold a cancelled run as finalized: it is never finalized, so never given an inconclusive verdict', () => {
    expect(isHuntRunFinalized({ hunt_run_mode: 'execute', hunt_run_status: 'cancelled', verdict_source: null })).toBe(true);
    expect(isHuntRunFinalized({ hunt_run_mode: 'execute', hunt_run_status: 'timeout', verdict_source: null })).toBe(false);
  });

  it('should tell the run of a deleted hunt from a hunt the reader cannot see', async () => {
    vi.mocked(internalLoadById).mockResolvedValue(undefined as never);
    expect(await isHuntRunHuntDeleted({ ...testContext }, { hunt_id: 'hunt-1' })).toBe(true);
    vi.mocked(internalLoadById).mockResolvedValue({ internal_id: 'hunt-1' } as never);
    expect(await isHuntRunHuntDeleted({ ...testContext }, { hunt_id: 'hunt-1' })).toBe(false);
  });
});

describe('Hunt manager sweep of orphan runs', () => {
  const { automationPageSize, automationMaxPagesPerTick } = HUNT_CONFIG;
  const pagesRead: string[][] = [];

  // The active runs, served page by page from the cursor of the scan, the way the engine pages them
  const servingRuns = (runs: Array<{ internal_id: string; [key: string]: unknown }>) => {
    const sorted = runs.map((run, index) => ({ ...run, sort: [index] }));
    vi.mocked(fullEntitiesList).mockImplementation(async (_context, _user, _types, opts) => {
      const start = opts?.after ? Number(cursorToOffset(opts.after)[0]) + 1 : 0;
      const first = opts?.first ?? sorted.length;
      const read: string[] = [];
      for (let offset = start; offset < sorted.length; offset += first) {
        const page = sorted.slice(offset, offset + first);
        read.push(...page.map((run) => run.internal_id));
        if (await opts?.callback?.(page as never) === false) {
          break;
        }
      }
      pagesRead.push(read);
      return [];
    });
    vi.mocked(storeLoadById).mockImplementation(async (_context, _user, id) => sorted.find((run) => run.internal_id === id) as never);
  };

  afterEach(() => {
    HUNT_CONFIG.automationPageSize = automationPageSize;
    HUNT_CONFIG.automationMaxPagesPerTick = automationMaxPagesPerTick;
    pagesRead.length = 0;
    vi.mocked(fullEntitiesList).mockReset();
    vi.mocked(internalFindByIds).mockReset();
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(patchAttribute).mockReset();
  });

  it('should cancel the runs of a deleted hunt, of a deleted connector and of a connector registered again since', async () => {
    servingRuns([
      { ...queued, internal_id: 'run-hunt-gone', hunt_id: 'hunt-gone', connector_id: 'connector-1', created_at: '2026-10-05T05:00:00.000Z' },
      { ...queued, internal_id: 'run-connector-gone', connector_id: 'connector-gone', created_at: '2026-10-05T05:00:00.000Z' },
      { ...queued, internal_id: 'run-redeployed', connector_id: 'connector-2', created_at: '2026-10-05T05:00:00.000Z' },
      { ...queued, internal_id: 'run-alive', connector_id: 'connector-1', created_at: '2026-10-05T05:00:00.000Z' },
    ]);
    vi.mocked(internalFindByIds).mockImplementation(async (_context, _user, _ids, options) => (options?.type === 'Hunt'
      ? [{ internal_id: 'hunt-1' }]
      : [{ internal_id: 'connector-1', created_at: '2026-10-01T00:00:00.000Z' }, { internal_id: 'connector-2', created_at: '2026-10-05T05:30:00.000Z' }]) as never);
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, id, _type, patch) => ({ element: { internal_id: id, ...patch } }) as never);
    expect(await cancelOrphanHuntRuns(testContext)).toEqual(3);
    const cancelledIds = vi.mocked(patchAttribute).mock.calls.map((call) => call[2]);
    expect(cancelledIds).toEqual(['run-hunt-gone', 'run-connector-gone', 'run-redeployed']);
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).toMatchObject({ error_message: HUNT_MESSAGES.runCancelledHuntDeleted });
    expect(vi.mocked(patchAttribute).mock.calls[2][4]).toMatchObject({ error_message: HUNT_MESSAGES.runCancelledConnectorDeleted });
  });

  it('should read a bounded number of pages per tick, resume at the next tick and cancel every orphan run in the end', async () => {
    HUNT_CONFIG.automationPageSize = 2;
    HUNT_CONFIG.automationMaxPagesPerTick = 1;
    servingRuns(Array.from({ length: 5 }, (_, index) => ({ ...queued, internal_id: `run-${index}`, hunt_id: 'hunt-gone' })));
    vi.mocked(internalFindByIds).mockResolvedValue([] as never);
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, id, _type, patch) => ({ element: { internal_id: id, ...patch } }) as never);
    const cancelledPerTick: number[] = [];
    for (let tick = 0; tick < 4; tick += 1) {
      cancelledPerTick.push(await cancelOrphanHuntRuns(testContext));
    }
    expect(pagesRead).toEqual([['run-0', 'run-1'], ['run-2', 'run-3'], ['run-4'], ['run-0', 'run-1']]);
    expect(cancelledPerTick.slice(0, 3)).toEqual([2, 2, 1]);
    // Each page loads the hunts and connectors of its own runs only
    expect(vi.mocked(internalFindByIds).mock.calls.filter((call) => call[3]?.type === 'Hunt').map((call) => call[2])).toEqual([
      ['hunt-gone'], ['hunt-gone'], ['hunt-gone'], ['hunt-gone'],
    ]);
  });
});

describe('Hunt statistics', () => {
  afterEach(() => {
    vi.mocked(fullEntitiesList).mockReset();
    vi.mocked(elAggregationCount).mockClear();
    vi.mocked(elHistogramCount).mockClear();
    vi.mocked(elHistogramSum).mockClear();
  });

  it('should count the runs of the existing hunts only, never a cancelled run, and the verdicts of completed runs only', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([{ internal_id: 'hunt-1' }, { internal_id: 'hunt-2' }] as never);
    await computeHuntStatistics(testContext, ADMIN_USER, {});
    const calls = vi.mocked(elAggregationCount).mock.calls.map((call) => call[3] as { field: string; filters: { filters: unknown[] } });
    const verdicts = calls.find((options) => options.field === 'verdict');
    const statuses = calls.find((options) => options.field === 'hunt_run_status');
    expect(statuses?.filters.filters).toEqual(expect.arrayContaining([
      { key: ['hunt_id'], values: ['hunt-1', 'hunt-2'] },
      { key: ['hunt_run_status'], values: ['cancelled'], operator: 'not_eq' },
    ]));
    expect(verdicts?.filters.filters).toContainEqual({ key: ['hunt_run_status'], values: ['completed'] });
  });

  it('should count nothing when no hunt exists, whatever runs deleted hunts left behind', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([] as never);
    const statistics = await computeHuntStatistics(testContext, ADMIN_USER, {});
    expect(elAggregationCount).not.toHaveBeenCalled();
    expect(statistics).toBeDefined();
  });
});
