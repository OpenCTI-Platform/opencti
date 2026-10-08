import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, fullRelationsList, internalLoadById } from '../../../../src/database/middleware-loader';
import { patchAttribute } from '../../../../src/database/middleware';
import { withHuntLock } from '../../../../src/modules/hunt/hunt-lock';
import { writeHuntCoverageResult } from '../../../../src/modules/hunt/hunt-coverage';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
  fullRelationsList: vi.fn(),
  internalLoadById: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-lock', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-lock')>(),
  withHuntLock: vi.fn(),
}));

const emulationRun = (id: string, platformId: string, hits: number): BasicStoreEntityHuntRun => ({
  internal_id: id,
  hunt_run_status: 'completed',
  hits_count: hits,
  security_coverage_id: 'coverage-1',
  aev_inject_id: 'inject-1',
  technique_id: 'technique-1',
  security_platform_id: platformId,
} as BasicStoreEntityHuntRun);

const scoreOf = (coverageInformation: { coverage_name: string; coverage_score: number }[]) => {
  return coverageInformation.find((information) => information.coverage_name === 'hunt_detected')?.coverage_score;
};

describe('Hunt coverage write-back of an emulation validation', () => {
  let stored: { coverage_name: string; coverage_score: number }[];
  let completedInIndex: BasicStoreEntityHuntRun[];

  beforeEach(() => {
    stored = [{ coverage_name: 'detection', coverage_score: 50 }];
    completedInIndex = [];
    vi.mocked(internalLoadById).mockResolvedValue({ internal_id: 'coverage-1', 'result-of': ['result-1'] } as never);
    vi.mocked(fullRelationsList).mockImplementation(async () => [{ internal_id: 'has-covered-1', coverage_information: stored }] as never);
    vi.mocked(fullEntitiesList).mockImplementation(async () => [...completedInIndex] as never);
  });

  afterEach(() => {
    vi.mocked(internalLoadById).mockReset();
    vi.mocked(fullRelationsList).mockReset();
    vi.mocked(fullEntitiesList).mockReset();
    vi.mocked(patchAttribute).mockReset();
    vi.mocked(withHuntLock).mockReset();
  });

  it('should never let a run without hits write over the detection of a concurrent run with hits on another platform', async () => {
    // One lock per key, granted in arrival order, like the platform lock
    const tails = new Map<string, Promise<unknown>>();
    vi.mocked(withHuntLock).mockImplementation(async (key, action) => {
      const previous = tails.get(key) ?? Promise.resolve();
      const current = previous.then(() => action());
      tails.set(key, current.catch(() => undefined));
      return current;
    });
    let releaseSlowWrite: () => void = () => {};
    const slowWrite = new Promise<void>((resolve) => {
      releaseSlowWrite = resolve;
    });
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, _id, _type, input) => {
      const { coverage_information: coverageInformation } = input as { coverage_information: typeof stored };
      // The run without hits read its siblings before the run with hits completed, and writes late
      if (scoreOf(coverageInformation) === 0) {
        await slowWrite;
      }
      stored = coverageInformation;
      return {} as never;
    });
    const withoutHits = emulationRun('run-no-hits', 'platform-a', 0);
    const withHits = emulationRun('run-hits', 'platform-b', 3);
    const first = writeHuntCoverageResult(testContext, withoutHits);
    await vi.waitFor(() => expect(vi.mocked(patchAttribute)).toHaveBeenCalledTimes(1));
    completedInIndex = [withoutHits, withHits];
    const second = writeHuntCoverageResult(testContext, withHits);
    releaseSlowWrite();
    await Promise.all([first, second]);
    expect(scoreOf(stored)).toEqual(100);
    // Both runs of the validation group took the same lock, whatever their security platform
    const keys = vi.mocked(withHuntLock).mock.calls.map(([key]) => key);
    expect(keys).toEqual(['hunt_coverage_coverage-1_inject-1_technique-1', 'hunt_coverage_coverage-1_inject-1_technique-1']);
  });

  it('should count the hits of the run being finalized even before the index exposes its completed status', async () => {
    vi.mocked(withHuntLock).mockImplementation(async (_key, action) => action());
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, _id, _type, input) => {
      stored = (input as { coverage_information: typeof stored }).coverage_information;
      return {} as never;
    });
    expect(await writeHuntCoverageResult(testContext, emulationRun('run-hits', 'platform-a', 1))).toEqual(1);
    expect(scoreOf(stored)).toEqual(100);
    expect(stored.find((information) => information.coverage_name === 'detection')?.coverage_score).toEqual(50);
  });

  it('should not lock nor write anything for a run outside an emulation validation', async () => {
    const standing = { internal_id: 'run-standing', hunt_run_status: 'completed', hits_count: 4 } as BasicStoreEntityHuntRun;
    expect(await writeHuntCoverageResult(testContext, standing)).toEqual(0);
    expect(vi.mocked(withHuntLock)).not.toHaveBeenCalled();
    expect(vi.mocked(patchAttribute)).not.toHaveBeenCalled();
  });
});
