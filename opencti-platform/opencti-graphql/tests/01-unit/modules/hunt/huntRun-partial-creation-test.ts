import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { createEntity } from '../../../../src/database/middleware';
import { resolveHuntConnectorTargets } from '../../../../src/modules/hunt/hunt-dispatch';
import { updateHuntRunInformation } from '../../../../src/modules/hunt/hunt-stats';
import { createHuntRuns } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  createEntity: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-dispatch', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-dispatch')>(),
  resolveHuntConnectorTargets: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-stats', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-stats')>(),
  updateHuntRunInformation: vi.fn(),
}));

const hunt = {
  internal_id: 'hunt-1',
  name: 'Encoded PowerShell',
  hunt_type: 'telemetry',
  hunt_status: 'active',
  native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr CommandLine="* -enc *"' }],
  escalation_threshold: 10,
  time_window_hours: 24,
} as unknown as BasicStoreEntityHunt;

const target = (index: number) => ({
  connector: { internal_id: `connector-${index}`, name: `Splunk Hunt ${index}` },
  securityPlatform: { internal_id: `platform-${index}`, name: `Splunk ${index}` },
});

describe('Hunt runs created in part', () => {
  beforeEach(() => {
    vi.mocked(fullEntitiesList).mockResolvedValue([] as never);
    vi.mocked(resolveHuntConnectorTargets).mockResolvedValue([target(1), target(2), target(3)] as never);
    vi.mocked(createEntity).mockReset();
    vi.mocked(updateHuntRunInformation).mockReset();
    vi.mocked(updateHuntRunInformation).mockResolvedValue(undefined as never);
  });

  it('should keep and return the runs already created when the creation of a later one fails', async () => {
    vi.mocked(createEntity)
      .mockImplementationOnce(async (_context, _user, input) => ({ ...input, internal_id: 'run-1' }) as never)
      .mockRejectedValueOnce(new Error('Lock timeout'));
    const runs = await createHuntRuns(testContext, hunt, { trigger: 'manual', requester: ADMIN_USER, dispatch: false });
    expect(runs.map((run) => run.internal_id)).toEqual(['run-1']);
    expect(createEntity).toHaveBeenCalledTimes(2);
    expect(updateHuntRunInformation).toHaveBeenCalledTimes(1);
  });

  it('should fail when no run could be created, so that the trigger is tried again', async () => {
    vi.mocked(createEntity).mockRejectedValueOnce(new Error('Lock timeout'));
    await expect(createHuntRuns(testContext, hunt, { trigger: 'manual', requester: ADMIN_USER, dispatch: false })).rejects.toThrow('Lock timeout');
    expect(updateHuntRunInformation).not.toHaveBeenCalled();
  });

  it('should return the runs created when their statistics cannot be recorded', async () => {
    vi.mocked(createEntity).mockImplementation(async (_context, _user, input) => ({ ...input, internal_id: `run-${(input as { connector_id: string }).connector_id}` }) as never);
    vi.mocked(updateHuntRunInformation).mockRejectedValueOnce(new Error('Engine unavailable'));
    const runs = await createHuntRuns(testContext, hunt, { trigger: 'manual', requester: ADMIN_USER, dispatch: false });
    expect(runs).toHaveLength(3);
  });
});
