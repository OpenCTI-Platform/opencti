import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { internalLoadById, storeLoadById, topEntitiesList } from '../../../../src/database/middleware-loader';
import { createEntity, patchAttribute } from '../../../../src/database/middleware';
import { resolveHuntConnectorTargets } from '../../../../src/modules/hunt/hunt-dispatch';
import { continueHuntIncident, createHuntIncidentInWorkspace, createHuntIncidentWorkspace, findOpenHuntIncident } from '../../../../src/modules/hunt/hunt-incident';
import { recordHuntHits } from '../../../../src/modules/hunt/huntHitRecord/huntHitRecord-domain';
import { upsertHuntSightings } from '../../../../src/modules/hunt/hunt-sightings';
import { updateHuntRunInformation } from '../../../../src/modules/hunt/hunt-stats';
import { huntLogicFingerprint } from '../../../../src/modules/hunt/hunt-logic';
import { huntHitKey } from '../../../../src/modules/hunt/hunt-utils';
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
  findOpenHuntIncident: vi.fn(async () => null),
  continueHuntIncident: vi.fn(async () => undefined),
}));

vi.mock('../../../../src/modules/hunt/huntHitRecord/huntHitRecord-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/huntHitRecord/huntHitRecord-domain')>(),
  recordHuntHits: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-sightings', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-sightings')>(),
  upsertHuntSightings: vi.fn(async () => ({ ids: [], created: 0, updated: 0 })),
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

const KEYS = Array.from({ length: 28 }, (_, index) => index.toString(16).padStart(64, '0'));

describe('Hits counted once across the runs of a hunt', () => {
  const loading = (run: BasicStoreEntityHuntRun) => {
    vi.mocked(storeLoadById).mockImplementation(async (_context, _user, _id, type) => (type === 'Hunt' ? hunt : { ...run, ...finalState() }) as never);
    vi.mocked(internalLoadById).mockResolvedValue(hunt as never);
    vi.mocked(updateHuntRunInformation).mockResolvedValue(undefined as never);
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, _id, _type, patch) => ({ element: { ...run, ...finalState(), ...patch } }) as never);
  };
  const autonomous = { ...running, hunt_run_trigger: 'standing', auto_escalation: true, security_platform_id: 'platform-1' } as BasicStoreEntityHuntRun;

  afterEach(() => {
    vi.mocked(patchAttribute).mockReset();
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(recordHuntHits).mockReset();
    vi.mocked(findOpenHuntIncident).mockReset();
    vi.mocked(findOpenHuntIncident).mockResolvedValue(null);
    vi.mocked(continueHuntIncident).mockClear();
    vi.mocked(createHuntIncidentWorkspace).mockClear();
    vi.mocked(createHuntIncidentInWorkspace).mockClear();
    vi.mocked(upsertHuntSightings).mockClear();
  });

  it('should open nothing when every hit of an autonomous run was seen before', async () => {
    loading(autonomous);
    vi.mocked(recordHuntHits).mockResolvedValue({ newCount: 0, recurringCount: 28 });
    await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'completed', hits_count: 28, hit_keys: KEYS } as never);
    expect(recordHuntHits).toHaveBeenCalledWith(testContext, expect.objectContaining({ huntId: 'hunt-1', securityPlatformId: 'platform-1', runId: 'run-1', keys: KEYS }));
    expect(createHuntIncidentWorkspace).not.toHaveBeenCalled();
    expect(finalState()).toMatchObject({ hits_count: 28, hits_new_count: 0, hits_recurring_count: 28, hits_identified: true, verdict_source: 'auto' });
    expect(updateHuntRunInformation).toHaveBeenLastCalledWith(testContext, 'hunt-1', expect.objectContaining({ last_hits_count: 28, last_new_hits_count: 0 }), { onlyIfNewer: true });
    // The sightings of the hunt are kept up to date all the same
    expect(upsertHuntSightings).toHaveBeenCalledTimes(1);
  });

  it('should escalate when the new hits alone reach the threshold', async () => {
    loading(autonomous);
    vi.mocked(recordHuntHits).mockResolvedValue({ newCount: 12, recurringCount: 16 });
    await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'completed', hits_count: 28, hit_keys: KEYS } as never);
    expect(createHuntIncidentWorkspace).toHaveBeenCalledTimes(1);
    expect(finalState()).toMatchObject({ hits_new_count: 12, incident_id: 'incident-1', incident_continued: false });
  });

  it('should add the hits to the incident still open from a previous run instead of opening a new one', async () => {
    loading(autonomous);
    vi.mocked(recordHuntHits).mockResolvedValue({ newCount: 12, recurringCount: 16 });
    vi.mocked(findOpenHuntIncident).mockResolvedValue({ incidentId: 'incident-0', draftId: 'draft-0' });
    await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'completed', hits_count: 28, hit_keys: KEYS } as never);
    expect(createHuntIncidentWorkspace).not.toHaveBeenCalled();
    expect(createHuntIncidentInWorkspace).not.toHaveBeenCalled();
    expect(continueHuntIncident).toHaveBeenCalledWith(testContext, hunt, expect.objectContaining({ internal_id: 'run-1' }), { incidentId: 'incident-0', draftId: 'draft-0' });
    expect(finalState()).toMatchObject({ incident_id: 'incident-0', draft_id: 'draft-0', incident_continued: true });
  });

  it('should count every hit as new, and say so, when the connector identifies none or the known hits cannot be read', async () => {
    loading(autonomous);
    await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'completed', hits_count: 28 } as never);
    expect(recordHuntHits).not.toHaveBeenCalled();
    expect(finalState()).toMatchObject({ hits_new_count: 28, hits_recurring_count: 0, hits_identified: false });
    vi.mocked(patchAttribute).mockReset();
    loading(autonomous);
    vi.mocked(recordHuntHits).mockRejectedValue(new Error('engine unavailable'));
    await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'completed', hits_count: 28, hit_keys: KEYS } as never);
    expect(finalState()).toMatchObject({ hits_new_count: 28, hits_recurring_count: 0, hits_identified: false });
  });

  it('should count every hit as new, and escalate on them, when the reported keys do not identify the hits', async () => {
    vi.mocked(recordHuntHits).mockResolvedValue({ newCount: 0, recurringCount: 28 });
    const reports = [
      { hit_keys: [] },
      { hit_keys: [...KEYS.slice(1), 'not a key'] },
      { hit_keys: KEYS.slice(1), hits_sample: [{ event_id: 'evt-1', host: 'FIN-WS-0142' }] },
    ];
    for (let index = 0; index < reports.length; index += 1) {
      vi.mocked(patchAttribute).mockReset();
      vi.mocked(createHuntIncidentWorkspace).mockClear();
      loading(autonomous);
      await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'completed', hits_count: 28, ...reports[index] } as never);
      expect(finalState()).toMatchObject({ hits_new_count: 28, hits_recurring_count: 0, hits_identified: false });
      expect(createHuntIncidentWorkspace).toHaveBeenCalledTimes(1);
    }
    expect(recordHuntHits).not.toHaveBeenCalled();
  });

  it('should keep the evidence attached while the run was running and add the report to it', async () => {
    const earlierId = 'indicator--4e0b2a28-1f0c-4c8e-9d0a-1b2c3d4e5f60';
    const reportedId = 'observed-data--9f8e7d6c-5b4a-4c3d-8e2f-1a0b9c8d7e6f';
    const reportedHit = { event_id: 'evt-1', timestamp: '2026-10-06T09:00:00.000Z', host: 'FIN-WS-0007' };
    const keys = [huntHitKey(reportedHit), ...KEYS.slice(1)];
    loading({
      ...autonomous,
      hits_count: 2,
      hits_new_count: 2,
      hits_recurring_count: 0,
      hits_sample: [{ hit_key: null, event_id: 'alert-1', timestamp: '2026-10-06T08:00:00.000Z', detection: null, matched: [], host: 'FIN-WS-0142', user: null, process: null }],
      evidence_sample: [{ field: 'host.name', value_hash: 'a'.repeat(64), value_preview: null, count: 2, matched: false }],
      result_ids: [earlierId],
      first_hit_at: '2026-10-06T08:00:00.000Z',
      last_hit_at: '2026-10-06T08:00:00.000Z',
    } as unknown as BasicStoreEntityHuntRun);
    vi.mocked(recordHuntHits).mockResolvedValue({ newCount: 12, recurringCount: 16 });
    await reportHuntRun(testContext, ADMIN_USER, 'run-1', {
      status: 'completed',
      hits_count: 28,
      hit_keys: keys,
      hits_sample: [reportedHit],
      evidence_sample: [{ field: 'process.command_line', value_hash: 'b'.repeat(64), count: 28 }],
      result_ids: [reportedId],
    } as never);
    // The evidence was matched against the known hits when it was attached: only the reported hits are matched now
    expect(recordHuntHits).toHaveBeenCalledWith(testContext, expect.objectContaining({ keys }));
    const state = finalState();
    expect(state).toMatchObject({
      hits_count: 30,
      hits_new_count: 14,
      hits_recurring_count: 16,
      first_hit_at: '2026-10-06T08:00:00.000Z',
      last_hit_at: '2026-10-06T09:00:00.000Z',
    });
    expect((state.hits_sample as { event_id: string }[]).map((hit) => hit.event_id)).toEqual(['alert-1', 'evt-1']);
    expect((state.evidence_sample as { field: string }[]).map((item) => item.field).sort()).toEqual(['host.name', 'process.command_line']);
    expect((state.result_ids as string[]).slice(0, 2)).toEqual([earlierId, reportedId]);
  });

  it('should never count more new hits than the run found when it reports more keys than hits', async () => {
    vi.mocked(recordHuntHits).mockResolvedValue({ newCount: 28, recurringCount: 0 });
    for (let index = 0; index < 2; index += 1) {
      const hitsCount = [0, 3][index];
      vi.mocked(patchAttribute).mockReset();
      loading(autonomous);
      await reportHuntRun(testContext, ADMIN_USER, 'run-1', { status: 'completed', hits_count: hitsCount, hit_keys: KEYS } as never);
      expect(finalState()).toMatchObject({ hits_count: hitsCount, hits_new_count: hitsCount, hits_recurring_count: 0, hits_identified: false });
    }
    expect(recordHuntHits).not.toHaveBeenCalled();
    expect(createHuntIncidentWorkspace).not.toHaveBeenCalled();
  });
});

describe('Time window of the recurring runs', () => {
  beforeEach(() => {
    vi.mocked(resolveHuntConnectorTargets).mockResolvedValue([
      { connector: { internal_id: 'connector-1', name: 'Splunk Hunt' }, securityPlatform: { internal_id: 'platform-1', name: 'Splunk' } },
    ] as never);
    vi.mocked(createEntity).mockImplementation(async (_context, _user, input) => ({ ...input, internal_id: 'run-2' }) as never);
    vi.mocked(updateHuntRunInformation).mockResolvedValue(undefined as never);
  });

  afterEach(() => {
    vi.mocked(createEntity).mockReset();
    vi.mocked(topEntitiesList).mockReset();
    vi.mocked(topEntitiesList).mockResolvedValue([]);
  });

  it('should search a scheduled run since the end of the previous completed run, with the lookback overlap', async () => {
    const previousEnd = new Date(Date.now() - 6 * 3600 * 1000).toISOString();
    vi.mocked(topEntitiesList).mockResolvedValueOnce([{ internal_id: 'run-1', time_window_end: previousEnd }] as never);
    await createHuntRuns(testContext, hunt, { trigger: 'schedule', dispatch: false });
    expect(createdRun().time_window_start).toEqual(new Date(new Date(previousEnd).getTime() - 15 * 60 * 1000).toISOString());
    expect(createdRun().continues_run_id).toEqual('run-1');
  });

  it('should continue only a previous run of the current logic of the hunt', async () => {
    // The search engine returns the previous run to a lookup of the logic it ran
    const previousEnd = new Date(Date.now() - 6 * 3600 * 1000).toISOString();
    vi.mocked(topEntitiesList).mockImplementation(async (_context, _user, _types, args) => {
      const filters = (args as { filters?: { filters: { key: string[]; values: string[] }[] } }).filters?.filters ?? [];
      const logic = filters.find((filter) => filter.key.includes('hunt_logic_fingerprint'));
      return (logic?.values[0] === huntLogicFingerprint(hunt) ? [{ internal_id: 'run-1', time_window_end: previousEnd }] : []) as never;
    });
    await createHuntRuns(testContext, hunt, { trigger: 'schedule', dispatch: false });
    expect(createdRun().continues_run_id).toEqual('run-1');
    expect(createdRun().hunt_logic_fingerprint).toEqual(huntLogicFingerprint(hunt));
    // A query edited since: no run of the new logic yet, the full time window is searched
    const edited = { ...hunt, native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr powershell -enc -nop' }] } as BasicStoreEntityHunt;
    await createHuntRuns(testContext, edited, { trigger: 'schedule', dispatch: false });
    const first = createdRun();
    expect(first.continues_run_id).toBeNull();
    expect(new Date(first.time_window_end as string).getTime() - new Date(first.time_window_start as string).getTime()).toEqual(24 * 3600 * 1000);
  });

  it('should search the full window for a first run, and keep the window a manual run asks for', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([]);
    await createHuntRuns(testContext, hunt, { trigger: 'standing', dispatch: false });
    const first = createdRun();
    expect(new Date(first.time_window_end as string).getTime() - new Date(first.time_window_start as string).getTime()).toEqual(24 * 3600 * 1000);
    expect(first.continues_run_id).toBeNull();
    vi.mocked(topEntitiesList).mockResolvedValue([{ internal_id: 'run-1', time_window_end: new Date().toISOString() }] as never);
    await createHuntRuns(testContext, hunt, { trigger: 'manual', requester: ADMIN_USER, timeWindowHours: 48, dispatch: false });
    const manual = createdRun();
    expect(new Date(manual.time_window_end as string).getTime() - new Date(manual.time_window_start as string).getTime()).toEqual(48 * 3600 * 1000);
    expect(manual.continues_run_id).toBeNull();
  });
});
