import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { redisGetManagerEventState } from '../../../src/database/redis';
import { defenseCoverageStreamStartFrom } from '../../../src/manager/defenseCoverageManager';

vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisGetManagerEventState: vi.fn(),
  redisSetManagerEventState: vi.fn(async () => {}),
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
