import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../src/modules/index';
import { runFullPassTick } from '../../../src/manager/graphAnalyticsManager';
import {
  getGraphAnalyticsComputeConfig,
  isFullPassInProgress,
  runFullPassStep,
  runInfrastructureClustering,
  shouldStartFullPass,
  startFullPass,
} from '../../../src/modules/graphAnalytics/graphAnalytics-compute';
import { redisGraphAnalyticsGetState } from '../../../src/database/redis';
import { GRAPH_ANALYTICS_MANAGER_USER } from '../../../src/utils/access';
import type { AuthContext } from '../../../src/types/user';

vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisGraphAnalyticsGetState: vi.fn(),
}));

vi.mock('../../../src/modules/graphAnalytics/graphAnalytics-compute', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/graphAnalytics/graphAnalytics-compute')>()),
  shouldStartFullPass: vi.fn(),
  startFullPass: vi.fn(),
  isFullPassInProgress: vi.fn(),
  runFullPassStep: vi.fn(),
  runInfrastructureClustering: vi.fn(),
}));

const context = { source: 'test', otp_mandatory: false } as unknown as AuthContext;
const user = GRAPH_ANALYTICS_MANAGER_USER;

describe('graph analytics manager full pass', () => {
  beforeEach(() => {
    vi.mocked(redisGraphAnalyticsGetState).mockReset().mockResolvedValue({});
    vi.mocked(shouldStartFullPass).mockReset().mockReturnValue(false);
    vi.mocked(startFullPass).mockReset();
    vi.mocked(isFullPassInProgress).mockReset().mockReturnValue(true);
    vi.mocked(runFullPassStep).mockReset();
    vi.mocked(runInfrastructureClustering).mockReset().mockResolvedValue({ clusters: 0, members: 0, skipped: false });
  });

  it('should do nothing when no full pass is in progress', async () => {
    vi.mocked(isFullPassInProgress).mockReturnValue(false);
    const outcome = await runFullPassTick(context, user, getGraphAnalyticsComputeConfig());
    expect(outcome).toBeNull();
    expect(runFullPassStep).not.toHaveBeenCalled();
    expect(runInfrastructureClustering).not.toHaveBeenCalled();
  });

  it('should start the pass when it is due', async () => {
    vi.mocked(shouldStartFullPass).mockReturnValue(true);
    vi.mocked(runFullPassStep).mockResolvedValue({ processed: 10, outcome: 'in_progress' });
    await runFullPassTick(context, user, getGraphAnalyticsComputeConfig());
    expect(startFullPass).toHaveBeenCalledTimes(1);
  });

  it('should not cluster while the sweep is still running', async () => {
    vi.mocked(runFullPassStep).mockResolvedValue({ processed: 10, outcome: 'in_progress' });
    const outcome = await runFullPassTick(context, user, getGraphAnalyticsComputeConfig());
    expect(outcome).toBe('in_progress');
    expect(runInfrastructureClustering).not.toHaveBeenCalled();
  });

  it('should not cluster a pass stopped at its entity cap', async () => {
    vi.mocked(runFullPassStep).mockResolvedValue({ processed: 10, outcome: 'capped' });
    const outcome = await runFullPassTick(context, user, getGraphAnalyticsComputeConfig());
    expect(outcome).toBe('capped');
    expect(runInfrastructureClustering).not.toHaveBeenCalled();
  });

  it('should cluster once the sweep reached the end of the entities', async () => {
    vi.mocked(runFullPassStep).mockResolvedValue({ processed: 10, outcome: 'completed' });
    const outcome = await runFullPassTick(context, user, getGraphAnalyticsComputeConfig());
    expect(outcome).toBe('completed');
    expect(runInfrastructureClustering).toHaveBeenCalledTimes(1);
  });
});
