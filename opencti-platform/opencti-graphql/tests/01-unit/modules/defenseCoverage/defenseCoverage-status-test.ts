import { beforeEach, describe, expect, it, vi } from 'vitest';
import { isModuleActivated } from '../../../../src/database/cluster-module';
import { isFullComputationRequested, requestFullDefenseCoverageComputation } from '../../../../src/modules/defenseCoverage/defenseCoverage-state';
import { getDefenseCoverageStatus, requestDefenseCoverageRecompute } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
import { DEFENSE_COVERAGE_MANAGER_ID } from '../../../../src/modules/defenseCoverage/defenseCoverage-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/cluster-module', () => ({
  isModuleActivated: vi.fn(async () => true),
}));

vi.mock('../../../../src/database/repository', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/repository')>()),
  connectorsForEnrichment: vi.fn(async () => []),
}));

vi.mock('../../../../src/modules/defenseCoverage/defenseCoverage-reader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/defenseCoverage/defenseCoverage-reader')>()),
  getDefenseSnapshot: vi.fn(async () => ({ version: 'none' })),
}));

vi.mock('../../../../src/modules/defenseCoverage/defenseCoverage-state', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/defenseCoverage/defenseCoverage-state')>()),
  requestFullDefenseCoverageComputation: vi.fn(async () => {}),
  isFullComputationRequested: vi.fn(async () => true),
  isFullComputationRunning: vi.fn(async () => false),
  getLastFullComputation: vi.fn(async () => undefined),
}));

const context = {} as AuthContext;
const user = {} as AuthUser;

describe('Defense coverage recomputation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should record the request when a node of the cluster runs the defense coverage manager', async () => {
    await expect(requestDefenseCoverageRecompute()).resolves.toEqual(true);
    expect(vi.mocked(isModuleActivated)).toHaveBeenCalledWith(DEFENSE_COVERAGE_MANAGER_ID);
    expect(vi.mocked(requestFullDefenseCoverageComputation)).toHaveBeenCalledTimes(1);
  });

  it('should refuse the request without recording it when no node runs the manager', async () => {
    vi.mocked(isModuleActivated).mockResolvedValueOnce(false);
    await expect(requestDefenseCoverageRecompute()).rejects.toThrow('The defense coverage manager is disabled: the defense coverage cannot be recomputed');
    expect(vi.mocked(requestFullDefenseCoverageComputation)).not.toHaveBeenCalled();
  });

  it('should report a requested computation as pending only while the computation is available', async () => {
    const available = await getDefenseCoverageStatus(context, user);
    expect(available.computation_available).toEqual(true);
    expect(available.full_computation_requested).toEqual(true);
    // A request recorded before the manager was disabled never keeps the matrix waiting
    vi.mocked(isModuleActivated).mockResolvedValueOnce(false);
    const unavailable = await getDefenseCoverageStatus(context, user);
    expect(unavailable.computation_available).toEqual(false);
    expect(unavailable.full_computation_requested).toEqual(false);
    vi.mocked(isFullComputationRequested).mockResolvedValueOnce(false);
    expect((await getDefenseCoverageStatus(context, user)).full_computation_requested).toEqual(false);
  });
});
