import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, storeLoadById } from '../../../../src/database/middleware-loader';
import { createEntity } from '../../../../src/database/middleware';
import { resolveHuntConnectorTargets } from '../../../../src/modules/hunt/hunt-dispatch';
import { findHuntTranslations } from '../../../../src/modules/hunt/hunt-logic';
import { updateHuntRunInformation } from '../../../../src/modules/hunt/hunt-stats';
import { createHuntRuns, startHuntRuns } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
  storeLoadById: vi.fn(),
  topEntitiesList: vi.fn(async () => []),
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

vi.mock('../../../../src/modules/hunt/hunt-access', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-access')>(),
  checkHuntEditAccess: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-logic', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-logic')>(),
  findHuntTranslation: vi.fn(async () => null),
  findHuntTranslations: vi.fn(async () => []),
}));

vi.mock('../../../../src/listener/UserActionListener', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/listener/UserActionListener')>(),
  publishUserAction: vi.fn(),
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

const PARTIAL_START = 'The hunt started on 1 of 3 security platforms: its runs could not be created on Splunk 2, Splunk 3, run it again on them';

const createFirstRunOnly = () => vi.mocked(createEntity)
  .mockImplementationOnce(async (_context, _user, input) => ({ ...input, internal_id: 'run-1' }) as never)
  .mockRejectedValueOnce(new Error('Lock timeout'));

describe('Hunt runs created in part', () => {
  beforeEach(() => {
    vi.mocked(fullEntitiesList).mockResolvedValue([] as never);
    vi.mocked(resolveHuntConnectorTargets).mockResolvedValue([target(1), target(2), target(3)] as never);
    vi.mocked(createEntity).mockReset();
    vi.mocked(updateHuntRunInformation).mockReset();
    vi.mocked(updateHuntRunInformation).mockResolvedValue(undefined as never);
    vi.mocked(publishUserAction).mockReset();
  });

  it('should keep and return the runs a recurring trigger created when the creation of a later one fails', async () => {
    createFirstRunOnly();
    const runs = await createHuntRuns(testContext, hunt, { trigger: 'schedule', dispatch: false });
    expect(runs.map((run) => run.internal_id)).toEqual(['run-1']);
    expect(createEntity).toHaveBeenCalledTimes(2);
    expect(updateHuntRunInformation).toHaveBeenCalledTimes(1);
  });

  it('should keep the runs a one-shot trigger created and fail, naming the security platforms left without a run', async () => {
    createFirstRunOnly();
    await expect(createHuntRuns(testContext, hunt, { trigger: 'playbook', dispatch: false })).rejects.toThrow(PARTIAL_START);
    expect(createEntity).toHaveBeenCalledTimes(2);
    expect(updateHuntRunInformation).toHaveBeenCalledTimes(1);
  });

  it('should record the user action of the runs a manual start created before it fails', async () => {
    vi.mocked(storeLoadById).mockResolvedValueOnce(hunt as never);
    createFirstRunOnly();
    await expect(startHuntRuns(testContext, ADMIN_USER, 'hunt-1', {})).rejects.toThrow(PARTIAL_START);
    expect(publishUserAction).toHaveBeenCalledTimes(1);
    expect(vi.mocked(publishUserAction).mock.calls[0][0]).toMatchObject({ message: 'runs hunt `Encoded PowerShell` on 1 platform(s)' });
  });

  it('should leave out of Run now the platforms the logic failed to translate to for good, and refuse it when none is left', async () => {
    const failedOn = (index: number) => ({
      state: 'failed',
      run: { internal_id: `run-failed-${index}`, security_platform_id: `platform-${index}`, connector_name: `Splunk Hunt ${index}`, error_message: 'HuntTranslationError: unsupported field' },
    });
    vi.mocked(createEntity).mockImplementation(async (_context, _user, input) => ({ ...input, internal_id: `run-${(input as { connector_id: string }).connector_id}` }) as never);
    vi.mocked(storeLoadById).mockResolvedValueOnce(hunt as never);
    vi.mocked(findHuntTranslations).mockResolvedValueOnce([failedOn(2)] as never);
    const runs = await startHuntRuns(testContext, ADMIN_USER, 'hunt-1', {});
    expect(runs.map((run) => run.security_platform_id)).toEqual(['platform-1', 'platform-3']);
    vi.mocked(createEntity).mockClear();
    vi.mocked(storeLoadById).mockResolvedValueOnce(hunt as never);
    vi.mocked(findHuntTranslations).mockResolvedValueOnce([failedOn(1), failedOn(2), failedOn(3)] as never);
    await expect(startHuntRuns(testContext, ADMIN_USER, 'hunt-1', {})).rejects.toThrow('The hunt cannot run: Splunk Hunt 1 cannot translate the hunt logic');
    expect(createEntity).not.toHaveBeenCalled();
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
