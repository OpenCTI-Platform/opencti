import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { redisGetManagerEventState, redisGetSetManagerEventState, redisSetManagerEventState } from '../../../src/database/redis';
import { defenseCoverageCronHandler, defenseCoverageStreamStartFrom } from '../../../src/manager/defenseCoverageManager';
import { computeDefenseCoverage } from '../../../src/modules/defenseCoverage/defenseCoverage-compute';

vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisGetManagerEventState: vi.fn(),
  redisSetManagerEventState: vi.fn(async () => {}),
  redisGetSetManagerEventState: vi.fn(async () => null),
  redisGetDefensePendingLevelChanges: vi.fn(async () => ({})),
}));
vi.mock('../../../src/lock/master-lock', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/lock/master-lock')>()),
  lockResources: vi.fn(async () => ({ unlock: async () => {} })),
}));
vi.mock('../../../src/modules/defenseCoverage/defenseCoverage-compute', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/defenseCoverage/defenseCoverage-compute')>()),
  computeDefenseCoverage: vi.fn(async () => ({ closed_gaps: 0 })),
}));
vi.mock('../../../src/modules/defenseCoverage/defenseCoverage-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/defenseCoverage/defenseCoverage-domain')>()),
  trackPendingValidationRequests: vi.fn(async () => 0),
}));
vi.mock('../../../src/manager/telemetryManager', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/manager/telemetryManager')>()),
  addDefenseGapClosedCount: vi.fn(async () => {}),
}));

const NOW = new Date('2026-10-06T12:00:00.000Z');
const eventIdOf = (date: string | Date) => `${new Date(date).getTime()}-0`;

const withState = (state: Record<string, string>) => {
  vi.mocked(redisGetManagerEventState).mockImplementation(async (key: string) => state[key] ?? null);
};

describe('Defense coverage manager stream start position', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should resume from the saved cursor', async () => {
    withState({
      defense_coverage_manager: '1791000000000-3',
      DEFENSE_COVERAGE_FULL_RUNNING_SINCE: '2026-10-06T11:59:00.000Z',
      DEFENSE_COVERAGE_FULL_RUN: '2026-10-05T12:00:00.000Z',
    });
    expect(await defenseCoverageStreamStartFrom()).toEqual('1791000000000-3');
  });

  it('should replay from the start of the full computation in progress on the first subscription', async () => {
    withState({
      DEFENSE_COVERAGE_FULL_RUNNING_SINCE: '2026-10-06T11:59:50.000Z',
      DEFENSE_COVERAGE_FULL_RUN: '2026-10-05T12:00:00.000Z',
    });
    expect(await defenseCoverageStreamStartFrom()).toEqual(eventIdOf('2026-10-06T11:59:50.000Z'));
  });

  it('should replay from the start of the completed full computation on the first subscription', async () => {
    withState({ DEFENSE_COVERAGE_FULL_RUNNING_SINCE: '', DEFENSE_COVERAGE_FULL_RUN: '2026-10-06T11:59:55.000Z' });
    expect(await defenseCoverageStreamStartFrom()).toEqual(eventIdOf('2026-10-06T11:59:55.000Z'));
  });

  it('should ignore a running mark left by a node stopped hours ago', async () => {
    withState({
      DEFENSE_COVERAGE_FULL_RUNNING_SINCE: '2026-10-06T08:00:00.000Z',
      DEFENSE_COVERAGE_FULL_RUN: '2026-10-06T11:00:00.000Z',
    });
    expect(await defenseCoverageStreamStartFrom()).toEqual(eventIdOf('2026-10-06T11:00:00.000Z'));
  });

  it('should start from the current position when no full computation has started yet', async () => {
    withState({});
    expect(await defenseCoverageStreamStartFrom()).toEqual(eventIdOf(NOW));
  });
});

describe('Defense coverage manager requested full computation', () => {
  let state: Record<string, string>;
  let operations: string[];

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
    // The last full computation is recent: only a request starts another one
    state = { DEFENSE_COVERAGE_FULL_RUN: '2026-10-06T11:00:00.000Z' };
    operations = [];
    withState(state);
    vi.mocked(redisSetManagerEventState).mockImplementation(async (key: string, value: string) => {
      operations.push(`set ${key}`);
      state[key] = value;
    });
    vi.mocked(redisGetSetManagerEventState).mockImplementation(async (key: string, value: string) => {
      operations.push(`getset ${key}`);
      const previous = state[key] ?? null;
      state[key] = value;
      return previous;
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should mark the computation running before consuming its request, so the status always shows one of them', async () => {
    state.DEFENSE_COVERAGE_FULL_REQUESTED = 'true';
    vi.mocked(computeDefenseCoverage).mockImplementationOnce(async () => {
      expect(state.DEFENSE_COVERAGE_FULL_REQUESTED).toEqual('false');
      expect(state.DEFENSE_COVERAGE_FULL_RUNNING_SINCE).toEqual(NOW.toISOString());
      return { closed_gaps: 0 } as never;
    });
    await defenseCoverageCronHandler();
    expect(vi.mocked(computeDefenseCoverage)).toHaveBeenCalledTimes(1);
    expect(operations.indexOf('set DEFENSE_COVERAGE_FULL_RUNNING_SINCE')).toBeLessThan(operations.indexOf('getset DEFENSE_COVERAGE_FULL_REQUESTED'));
    expect(state.DEFENSE_COVERAGE_FULL_RUNNING_SINCE).toEqual('');
  });

  it('should keep a request made during the computation for the next run', async () => {
    state.DEFENSE_COVERAGE_FULL_REQUESTED = 'true';
    vi.mocked(computeDefenseCoverage).mockImplementationOnce(async () => {
      state.DEFENSE_COVERAGE_FULL_REQUESTED = 'true';
      return { closed_gaps: 0 } as never;
    });
    await defenseCoverageCronHandler();
    expect(state.DEFENSE_COVERAGE_FULL_REQUESTED).toEqual('true');
  });

  it('should neither mark nor consume anything when no computation is due or requested', async () => {
    await defenseCoverageCronHandler();
    expect(vi.mocked(computeDefenseCoverage)).not.toHaveBeenCalled();
    expect(operations).toEqual([]);
  });
});
