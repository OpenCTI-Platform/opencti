import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, internalLoadById } from '../../../../src/database/middleware-loader';
import { dispatchQueuedHuntRuns, newHuntTickBudget } from '../../../../src/modules/hunt/hunt-automation';
import { dispatchHuntRun } from '../../../../src/modules/hunt/hunt-dispatch';
import { HUNT_CONFIG } from '../../../../src/modules/hunt/hunt-utils';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
  internalLoadById: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-dispatch', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-dispatch')>(),
  dispatchHuntRun: vi.fn(),
}));

const queuedRun = (index: number, connectorId: string): BasicStoreEntityHuntRun => ({
  internal_id: `run-${connectorId}-${index}`,
  hunt_id: 'hunt-1',
  connector_id: connectorId,
  hunt_run_status: 'queued',
  hunt_run_mode: 'execute',
} as BasicStoreEntityHuntRun);

// The queue of executed runs, read page by page like the loader does until a page callback stops it: a dispatched run
// leaves the queue, and the runs of the connectors the query excludes are not read
const serveQueue = (queue: BasicStoreEntityHuntRun[]) => {
  vi.mocked(fullEntitiesList).mockImplementation(async (_context, _user, _types, opts) => {
    const modeFilter = opts?.filters?.filters.find((filter) => filter.key.includes('hunt_run_mode'));
    const excluded = opts?.filters?.filters.find((filter) => filter.key.includes('connector_id'))?.values ?? [];
    const dispatched = new Set(vi.mocked(dispatchHuntRun).mock.calls.map(([, run]) => run.internal_id));
    const runs = modeFilter?.values.includes('execute')
      ? queue.filter((run) => !excluded.includes(run.connector_id) && !dispatched.has(run.internal_id))
      : [];
    const first = opts?.first ?? runs.length;
    for (let offset = 0; offset < runs.length; offset += first) {
      const proceed = await opts?.callback?.(runs.slice(offset, offset + first));
      if (proceed === false) {
        break;
      }
    }
    return [];
  });
};

const dispatchedConnectors = () => vi.mocked(dispatchHuntRun).mock.calls.map(([, run]) => run.connector_id);

describe('Hunt run dispatch budget of a manager tick', () => {
  const { maxRunsPerTick } = HUNT_CONFIG;

  beforeEach(() => {
    vi.mocked(internalLoadById).mockResolvedValue({ internal_id: 'hunt-1', name: 'Hunt' } as BasicStoreEntityHunt as never);
  });

  afterEach(() => {
    HUNT_CONFIG.maxRunsPerTick = maxRunsPerTick;
    vi.mocked(dispatchHuntRun).mockReset();
    vi.mocked(fullEntitiesList).mockReset();
  });

  it('should try a failing connector once per tick and keep dispatching the runs of the others', async () => {
    HUNT_CONFIG.maxRunsPerTick = 10;
    serveQueue([...Array.from({ length: 5 }, (_, index) => queuedRun(index, 'down')), queuedRun(0, 'up'), queuedRun(1, 'up')]);
    vi.mocked(dispatchHuntRun).mockImplementation(async (_context, run) => {
      if (run.connector_id === 'down') {
        throw new Error('Queue publication failed');
      }
      return true;
    });
    expect(await dispatchQueuedHuntRuns(testContext)).toEqual(2);
    expect(dispatchedConnectors()).toEqual(['down', 'up', 'up']);
  });

  it('should count failed dispatches against the budget of the tick', async () => {
    HUNT_CONFIG.maxRunsPerTick = 3;
    serveQueue(Array.from({ length: 8 }, (_, index) => queuedRun(0, `connector-${index}`)));
    vi.mocked(dispatchHuntRun).mockRejectedValue(new Error('Work creation failed'));
    expect(await dispatchQueuedHuntRuns(testContext)).toEqual(0);
    expect(dispatchHuntRun).toHaveBeenCalledTimes(3);
  });

  it('should count a run deferred by its connector budget once per connector and tick', async () => {
    HUNT_CONFIG.maxRunsPerTick = 2;
    serveQueue([queuedRun(0, 'saturated'), queuedRun(1, 'saturated'), queuedRun(0, 'free'), queuedRun(1, 'free')]);
    vi.mocked(dispatchHuntRun).mockImplementation(async (_context, run) => run.connector_id !== 'saturated');
    expect(await dispatchQueuedHuntRuns(testContext)).toEqual(1);
    expect(dispatchedConnectors()).toEqual(['saturated', 'free']);
  });

  it('should bound the attempts of a tick however many connectors defer their runs', async () => {
    HUNT_CONFIG.maxRunsPerTick = 3;
    serveQueue(Array.from({ length: 8 }, (_, index) => queuedRun(0, `saturated-${index}`)));
    vi.mocked(dispatchHuntRun).mockResolvedValue(false);
    expect(await dispatchQueuedHuntRuns(testContext)).toEqual(0);
    expect(dispatchHuntRun).toHaveBeenCalledTimes(3);
  });

  it('should dispatch the queue within what the earlier phases of the tick left of its budget', async () => {
    HUNT_CONFIG.maxRunsPerTick = 5;
    serveQueue(Array.from({ length: 5 }, (_, index) => queuedRun(index, 'up')));
    vi.mocked(dispatchHuntRun).mockResolvedValue(true);
    // Retries and autonomous hunts dispatched three runs before the queue is served
    const budget = newHuntTickBudget();
    budget.remaining -= 3;
    expect(await dispatchQueuedHuntRuns(testContext, budget)).toEqual(2);
    expect(budget.remaining).toEqual(0);
    // A spent budget dispatches nothing and reads no queue
    vi.mocked(fullEntitiesList).mockClear();
    expect(await dispatchQueuedHuntRuns(testContext, budget)).toEqual(0);
    expect(fullEntitiesList).not.toHaveBeenCalled();
  });

  it('should never page through the backlog of an offline connector', async () => {
    HUNT_CONFIG.maxRunsPerTick = 3;
    // A connector offline for long: its queued runs come first, far beyond one page
    serveQueue([...Array.from({ length: 40 }, (_, index) => queuedRun(index, 'offline')), queuedRun(0, 'up'), queuedRun(1, 'up')]);
    vi.mocked(dispatchHuntRun).mockImplementation(async (_context, run) => run.connector_id !== 'offline');
    expect(await dispatchQueuedHuntRuns(testContext)).toEqual(2);
    expect(dispatchedConnectors()).toEqual(['offline', 'up', 'up']);
    // The first page, then the queue read again without the offline connector
    const reads = vi.mocked(fullEntitiesList).mock.calls.filter(([, , , opts]) => opts?.filters?.filters.some((filter) => filter.values.includes('execute')));
    expect(reads.length).toEqual(2);
    expect(reads[1][3]?.filters?.filters.find((filter) => filter.key.includes('connector_id'))?.values).toEqual(['offline']);
  });
});
