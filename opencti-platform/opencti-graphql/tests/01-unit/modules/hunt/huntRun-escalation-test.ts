import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { internalLoadById, storeLoadById } from '../../../../src/database/middleware-loader';
import { createEntity, patchAttribute } from '../../../../src/database/middleware';
import { resolveHuntConnectorTargets } from '../../../../src/modules/hunt/hunt-dispatch';
import { createHuntIncidentInWorkspace, createHuntIncidentWorkspace } from '../../../../src/modules/hunt/hunt-incident';
import { updateHuntRunInformation } from '../../../../src/modules/hunt/hunt-stats';
import { createHuntRuns, isAutoEscalatedHuntRun, reportHuntRun, setHuntRunVerdict } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalLoadById: vi.fn(),
  storeLoadById: vi.fn(),
  topEntitiesList: vi.fn(async () => []),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  createEntity: vi.fn(),
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/redis')>(),
  notify: vi.fn(async (_topic, instance) => instance),
}));

vi.mock('../../../../src/modules/hunt/hunt-lock', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-lock')>(),
  withHuntLock: vi.fn(async (_key, action) => action()),
}));

vi.mock('../../../../src/modules/hunt/hunt-dispatch', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-dispatch')>(),
  listHuntConnectors: vi.fn(async () => []),
  resolveHuntConnectorTargets: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-incident', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-incident')>(),
  createHuntIncidentWorkspace: vi.fn(async () => 'draft-1'),
  createHuntIncidentInWorkspace: vi.fn(async () => 'incident-1'),
}));

vi.mock('../../../../src/modules/hunt/hunt-stats', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-stats')>(),
  updateHuntRunInformation: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-coverage', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-coverage')>(),
  writeHuntCoverageResult: vi.fn(),
}));

vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>(),
  checkEnterpriseEdition: vi.fn(async () => {
    throw new Error('No triage in this test');
  }),
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
  native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr powershell -enc' }],
  escalation_threshold: 10,
  time_window_hours: 24,
} as unknown as BasicStoreEntityHunt;

const createdRun = () => vi.mocked(createEntity).mock.calls.at(-1)?.[2] as Record<string, unknown>;
const patches = () => vi.mocked(patchAttribute).mock.calls.map((call) => call[4] as Record<string, unknown>);
const finalState = () => Object.assign({}, ...patches());

describe('Escalation decided at the creation of a run', () => {
  beforeEach(() => {
    vi.mocked(resolveHuntConnectorTargets).mockResolvedValue([
      { connector: { internal_id: 'connector-1', name: 'Splunk Hunt' }, securityPlatform: { internal_id: 'platform-1', name: 'Splunk' } },
    ] as never);
    vi.mocked(createEntity).mockImplementation(async (_context, _user, input) => ({ ...input, internal_id: 'run-1' }) as never);
    vi.mocked(updateHuntRunInformation).mockResolvedValue(undefined as never);
  });

  afterEach(() => {
    vi.mocked(createEntity).mockReset();
  });

  it('should leave a run started by hand to the analyst, unless its hunt escalates manual runs', async () => {
    await createHuntRuns(testContext, hunt, { trigger: 'manual', requester: ADMIN_USER, dispatch: false });
    expect(createdRun().auto_escalation).toBe(false);
    await createHuntRuns(testContext, { ...hunt, escalate_manual_runs: true }, { trigger: 'manual', requester: ADMIN_USER, dispatch: false });
    expect(createdRun().auto_escalation).toBe(true);
  });

  it('should keep escalating scheduled and autonomous runs, and a retry as the run it replaces', async () => {
    await createHuntRuns(testContext, hunt, { trigger: 'schedule', dispatch: false });
    expect(createdRun().auto_escalation).toBe(true);
    await createHuntRuns(testContext, hunt, { trigger: 'retry', autoEscalation: true, dispatch: false });
    expect(createdRun().auto_escalation).toBe(true);
    await createHuntRuns(testContext, hunt, { trigger: 'retry', autoEscalation: false, dispatch: false });
    expect(createdRun().auto_escalation).toBe(false);
    await createHuntRuns(testContext, hunt, { trigger: 'preview', mode: 'preview', requester: ADMIN_USER, dispatch: false });
    expect(createdRun().auto_escalation).toBeNull();
  });

  it('should keep escalating the runs created before the decision was recorded', () => {
    expect(isAutoEscalatedHuntRun({})).toBe(true);
    expect(isAutoEscalatedHuntRun({ auto_escalation: false })).toBe(false);
  });
});

const running = {
  internal_id: 'run-1',
  hunt_id: 'hunt-1',
  hunt_run_status: 'running',
  hunt_run_mode: 'execute',
  hunt_run_trigger: 'manual',
  connector_name: 'Splunk Hunt',
  attempt: 1,
  verdict: 'pending',
  work_id: 'work-1',
} as unknown as BasicStoreEntityHuntRun;

describe('Escalation at the end of a run above the threshold', () => {
  const loading = (run: BasicStoreEntityHuntRun) => {
    vi.mocked(storeLoadById).mockImplementation(async (_context, _user, _id, type) => (type === 'Hunt' ? hunt : { ...run, ...finalState() }) as never);
    vi.mocked(internalLoadById).mockResolvedValue(hunt as never);
    vi.mocked(updateHuntRunInformation).mockResolvedValue(undefined as never);
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, _id, _type, patch) => ({ element: { ...run, ...finalState(), ...patch } }) as never);
  };

  afterEach(() => {
    vi.mocked(patchAttribute).mockReset();
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(createHuntIncidentWorkspace).mockClear();
    vi.mocked(createHuntIncidentInWorkspace).mockClear();
  });

  it('should open no incident draft for a manual run, its hits waiting for the verdict', async () => {
    loading({ ...running, auto_escalation: false });
    await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'completed', hits_count: 28 } as never);
    expect(createHuntIncidentWorkspace).not.toHaveBeenCalled();
    expect(finalState()).toMatchObject({ hunt_run_status: 'completed', verdict: 'pending', verdict_source: 'auto' });
    expect(finalState().incident_id).toBeUndefined();
  });

  it('should open the incident draft of an autonomous run by itself', async () => {
    loading({ ...running, hunt_run_trigger: 'schedule', auto_escalation: true });
    await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'completed', hits_count: 28 } as never);
    expect(createHuntIncidentWorkspace).toHaveBeenCalledTimes(1);
    expect(finalState()).toMatchObject({ draft_id: 'draft-1', incident_id: 'incident-1' });
  });

  it('should offer the incident at verdict time: a true positive opens it unless the analyst declines', async () => {
    const completed = { ...running, hunt_run_status: 'completed', hits_count: 28, verdict_source: 'auto', auto_escalation: false } as BasicStoreEntityHuntRun;
    loading(completed);
    await setHuntRunVerdict(testContext, ADMIN_USER, 'run-1', { verdict: 'true_positive', create_incident: false } as never);
    expect(createHuntIncidentWorkspace).not.toHaveBeenCalled();
    expect(finalState()).toMatchObject({ verdict: 'true_positive', verdict_source: 'analyst' });
    expect(finalState().incident_id).toBeUndefined();
    vi.mocked(patchAttribute).mockReset();
    loading(completed);
    await setHuntRunVerdict(testContext, ADMIN_USER, 'run-1', { verdict: 'true_positive' } as never);
    expect(createHuntIncidentWorkspace).toHaveBeenCalledTimes(1);
    expect(finalState()).toMatchObject({ verdict: 'true_positive', draft_id: 'draft-1', incident_id: 'incident-1' });
  });
});
