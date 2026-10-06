import gql from 'graphql-tag';
import { v4 as uuidv4 } from 'uuid';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, testContext, USER_CONNECTOR } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { deleteElementById, patchAttribute } from '../../../src/database/middleware';
import * as middlewareLoader from '../../../src/database/middleware-loader';
import { resetCacheForEntity } from '../../../src/database/cache';
import * as playbookManager from '../../../src/manager/playbookManager/playbookManager';
import { FilterMode, OrderingMode, PirType } from '../../../src/generated/graphql';
import { deletePir, pirAdd, pirFlagElement, pirUnflagElement } from '../../../src/modules/pir/pir-domain';
import { ENTITY_TYPE_CONNECTOR } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../src/modules/securityPlatform/securityPlatform-types';
import { type BasicStoreEntityHunt, ENTITY_TYPE_HUNT } from '../../../src/modules/hunt/hunt-types';
import {
  type BasicStoreEntityHuntRun,
  ENTITY_TYPE_HUNT_RUN,
  HUNT_RUN_ACTIVE_STATUSES,
  HUNT_RUN_MODE_PREVIEW,
  HUNT_RUN_STATUS_QUEUED,
  HUNT_RUN_STATUS_TIMEOUT,
  HUNT_RUN_TRIGGER_MANUAL,
  HUNT_RUN_TRIGGER_PIR,
  HUNT_RUN_TRIGGER_PLAYBOOK,
  HUNT_RUN_TRIGGER_PREVIEW,
  HUNT_RUN_TRIGGER_RETRY,
  HUNT_RUN_TRIGGER_SCHEDULE,
  HUNT_RUN_TRIGGER_STANDING,
} from '../../../src/modules/hunt/huntRun/huntRun-types';
import { createHuntRuns, expireHuntRun, findHuntRunResultIds, findHuntRunResults, retryHuntRun } from '../../../src/modules/hunt/huntRun/huntRun-domain';
import { HUNT_CONFIG } from '../../../src/modules/hunt/hunt-utils';
import { dispatchHuntRun } from '../../../src/modules/hunt/hunt-dispatch';
import * as enterpriseEdition from '../../../src/enterprise-edition/ee';
import {
  dispatchQueuedHuntRuns,
  expireStaleHuntRuns,
  HUNT_MANAGER_STREAM_STATE,
  processStandingHunts,
  purgeExpiredHuntRuns,
  reconcilePirActivatedHunts,
  requeueUnpublishedHuntRuns,
  resumeSettledHuntPlaybooks,
  retryFailedHuntRuns,
  runScheduledHunts,
} from '../../../src/modules/hunt/hunt-automation';
import { redisSetManagerEventState } from '../../../src/database/redis';
import * as rabbitmq from '../../../src/database/rabbitmq';
import * as workDomain from '../../../src/domain/work';
import { PLAYBOOK_HUNT_COMPONENT } from '../../../src/modules/playbook/components/hunt-component';
import { playbookBundleElementsToApply } from '../../../src/modules/playbook/playbook-types';
import { findPlaybookHuntRuns, loadHuntRunResultsForPlaybook } from '../../../src/modules/hunt/hunt-playbook';
import * as huntRunDomain from '../../../src/modules/hunt/huntRun/huntRun-domain';
import * as middleware from '../../../src/database/middleware';
import * as repository from '../../../src/database/repository';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

const CONNECTOR_ID = '6d2f4c1e-8a3b-4f6e-9c7d-2b5a1e0f3d02';
const SIGMA_RULE = `title: Hunt manager test encoded command
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: ' -enc '
  condition: selection
`;

const hoursAgo = (hours: number) => new Date(Date.now() - hours * 3600000).toISOString();

const loadRun = (id: string) => middlewareLoader.internalLoadById<BasicStoreEntityHuntRun>(testContext, ADMIN_USER, id, { type: ENTITY_TYPE_HUNT_RUN });
const loadHunt = (id: string) => middlewareLoader.internalLoadById<BasicStoreEntityHunt>(testContext, ADMIN_USER, id, { type: ENTITY_TYPE_HUNT });

const listHuntRuns = (huntId: string) => middlewareLoader.topEntitiesList<BasicStoreEntityHuntRun>(testContext, ADMIN_USER, [ENTITY_TYPE_HUNT_RUN], {
  first: 100,
  orderBy: 'created_at',
  orderMode: OrderingMode.Asc,
  filters: { mode: FilterMode.And, filters: [{ key: ['hunt_id'], values: [huntId] }], filterGroups: [] },
  noFiltersChecking: true,
});

describe('Hunt manager', () => {
  let intrusionSetId: string;
  let securityPlatformId: string;
  let huntId: string;

  beforeAll(async () => {
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue(undefined);
    const intrusionSet = await queryAsAdminWithSuccess({
      query: gql`mutation IntrusionSetAdd($input: IntrusionSetAddInput!) { intrusionSetAdd(input: $input) { id } }`,
      variables: { input: { name: 'Hunt manager test intrusion set' } },
    });
    intrusionSetId = intrusionSet.data?.intrusionSetAdd.id;
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: gql`mutation RegisterConnector($input: RegisterConnectorInput) { registerConnector(input: $input) { id } }`,
      variables: { input: { id: CONNECTOR_ID, name: 'Hunt manager test connector', type: 'INTERNAL_HUNT', scope: ['splunk'], auto: false, only_contextual: false } },
    });
    const registration = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: gql`mutation HuntConnectorRegister($input: HuntConnectorRegisterInput!) {
        huntConnectorRegister(input: $input) { id securityPlatform { id } }
      }`,
      variables: { input: { connector_id: CONNECTOR_ID, platform: 'splunk', languages: ['spl'], security_platform_name: 'Hunt manager test Splunk' } },
    });
    securityPlatformId = registration.data?.huntConnectorRegister.securityPlatform.id;
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    const hunt = await queryAsAdminWithSuccess({
      query: gql`mutation HuntAdd($input: HuntAddInput!) { huntAdd(input: $input) { id } }`,
      variables: {
        input: {
          name: 'Hunt manager test hunt',
          sigma_rule: SIGMA_RULE,
          huntTargets: [intrusionSetId],
          native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr CommandLine="* -enc *"' }],
        },
      },
    });
    huntId = hunt.data?.huntAdd.id;
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    const runs = await listHuntRuns(huntId);
    for (let index = 0; index < runs.length; index += 1) {
      await deleteElementById(testContext, ADMIN_USER, runs[index].internal_id, ENTITY_TYPE_HUNT_RUN);
    }
    await queryAsAdmin({ query: gql`mutation HuntDelete($id: ID!) { huntDelete(id: $id) }`, variables: { id: huntId } });
    await queryAsAdmin({ query: gql`mutation DeleteConnector($id: ID!) { deleteConnector(id: $id) }`, variables: { id: CONNECTOR_ID } });
    if (securityPlatformId) {
      await deleteElementById(testContext, ADMIN_USER, securityPlatformId, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
    }
    await deleteElementById(testContext, ADMIN_USER, intrusionSetId, ENTITY_TYPE_INTRUSION_SET);
  });

  it('should expire a run its connector never completed and plan its retry', async () => {
    const hunt = await loadHunt(huntId);
    const [run] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL });
    expect((await loadRun(run.internal_id)).dispatched_at).toBeTruthy();
    await patchAttribute(testContext, ADMIN_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { dispatched_at: hoursAgo(2) });
    expect(await expireStaleHuntRuns(testContext)).toBeGreaterThanOrEqual(1);
    const expired = await loadRun(run.internal_id);
    expect(expired.hunt_run_status).toEqual(HUNT_RUN_STATUS_TIMEOUT);
    expect(expired.error_message).toContain('did not complete the run');
    expect(expired.next_retry_at).toBeTruthy();
  });

  it('should retry a failed run once its backoff elapsed, exactly once', async () => {
    const [expired] = (await listHuntRuns(huntId)).filter((run) => run.hunt_run_status === HUNT_RUN_STATUS_TIMEOUT);
    await patchAttribute(testContext, ADMIN_USER, expired.internal_id, ENTITY_TYPE_HUNT_RUN, { next_retry_at: hoursAgo(1) });
    expect(await retryFailedHuntRuns(testContext)).toBeGreaterThanOrEqual(1);
    expect((await loadRun(expired.internal_id)).next_retry_at).toBeFalsy();
    const retries = (await listHuntRuns(huntId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_RETRY);
    expect(retries).toHaveLength(1);
    expect(retries[0].attempt).toEqual(2);
    expect(retries[0].connector_id).toEqual(CONNECTOR_ID);
    expect(retries[0].time_window_start).toEqual(expired.time_window_start);
    await retryFailedHuntRuns(testContext);
    expect((await listHuntRuns(huntId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_RETRY)).toHaveLength(1);
  });

  it('should dispatch the runs left queued', async () => {
    const hunt = await loadHunt(huntId);
    const [run] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false });
    expect(run.dispatched_at).toBeFalsy();
    expect(await dispatchQueuedHuntRuns(testContext)).toBeGreaterThanOrEqual(1);
    const dispatched = await loadRun(run.internal_id);
    expect(dispatched.dispatched_at).toBeTruthy();
    expect(dispatched.work_id).toBeTruthy();
  });

  it('should run a due scheduled hunt and plan its next occurrence', async () => {
    await patchAttribute(testContext, ADMIN_USER, huntId, ENTITY_TYPE_HUNT, { hunt_schedule: '0 */6 * * *', next_run_at: hoursAgo(1) });
    expect(await runScheduledHunts(testContext)).toBeGreaterThanOrEqual(1);
    const hunt = await loadHunt(huntId);
    expect(new Date(hunt.next_run_at as string).getTime()).toBeGreaterThan(Date.now());
    expect((await listHuntRuns(huntId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_SCHEDULE)).toHaveLength(1);
    await runScheduledHunts(testContext);
    expect((await listHuntRuns(huntId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_SCHEDULE)).toHaveLength(1);
  });

  it('should arm a PIR activated hunt while a PIR flags one of its targets', async () => {
    await patchAttribute(testContext, ADMIN_USER, huntId, ENTITY_TYPE_HUNT, { hunt_schedule: 'manual', next_run_at: null, hunt_pir_activation: true });
    const criterion = { weight: 1, filters: { mode: FilterMode.And, filters: [{ key: ['entity_type'], values: [ENTITY_TYPE_INTRUSION_SET] }], filterGroups: [] } };
    const pir = await pirAdd(testContext, ADMIN_USER, {
      name: 'Hunt manager test PIR',
      pir_type: PirType.ThreatLandscape,
      pir_rescan_days: 0,
      pir_filters: { mode: FilterMode.And, filters: [], filterGroups: [] },
      pir_criteria: [criterion],
    });
    const flag = { relationshipId: uuidv4(), sourceId: intrusionSetId };
    try {
      await reconcilePirActivatedHunts(testContext);
      expect((await loadHunt(huntId)).hunt_pir_armed).not.toBe(true);
      await pirFlagElement(testContext, ADMIN_USER, pir.standard_id, { ...flag, matchingCriteria: [criterion] });
      expect(await reconcilePirActivatedHunts(testContext)).toBeGreaterThanOrEqual(1);
      const armed = await loadHunt(huntId);
      expect(armed.hunt_pir_armed).toBe(true);
      expect(armed.hunt_pir_armed_at).toBeTruthy();
      expect(armed.hunt_status).toEqual('active');
      expect((await listHuntRuns(huntId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_PIR)).toHaveLength(1);
      // Still flagged: no new run
      await reconcilePirActivatedHunts(testContext);
      expect((await listHuntRuns(huntId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_PIR)).toHaveLength(1);
      // A standing trigger still pending when the hunt is disarmed is dropped, not served once the hunt is armed again
      await patchAttribute(testContext, ADMIN_USER, huntId, ENTITY_TYPE_HUNT, { hunt_schedule: 'standing', next_run_at: hoursAgo(1) });
      await pirUnflagElement(testContext, ADMIN_USER, pir.standard_id, flag);
      await reconcilePirActivatedHunts(testContext);
      const disarmed = await loadHunt(huntId);
      expect(disarmed.hunt_pir_armed).toBe(false);
      expect(disarmed.hunt_status).toEqual('active');
      expect(disarmed.next_run_at ?? null).toBeNull();
    } finally {
      await patchAttribute(testContext, ADMIN_USER, huntId, ENTITY_TYPE_HUNT, { hunt_pir_activation: false, hunt_schedule: 'manual', next_run_at: null });
      await deletePir(testContext, ADMIN_USER, pir.id);
    }
  });

  it('should resume a playbook waiting on a hunt step once its runs are settled, exactly once', async () => {
    const resume = vi.spyOn(playbookManager, 'playbookStepExecution').mockResolvedValue(true);
    const hunt = await loadHunt(huntId);
    const executionId = uuidv4();
    const playbookContext = {
      playbook_id: uuidv4(),
      step_id: 'hunt-step',
      previous_step_id: 'entry-step',
      execution_id: executionId,
      event_id: 'event-id',
      data_instance_id: intrusionSetId,
      execution_start: new Date().toISOString(),
      include_results: false,
      bundle: JSON.stringify({ id: 'bundle--hunt-manager-test', type: 'bundle', objects: [] }),
      previous_bundle: JSON.stringify({ id: 'bundle--hunt-manager-test', type: 'bundle', objects: [] }),
    };
    const [leader] = await createHuntRuns(testContext, hunt, {
      trigger: HUNT_RUN_TRIGGER_PLAYBOOK,
      dispatch: false,
      playbook: { playbookId: playbookContext.playbook_id, executionId, stepId: 'hunt-step', context: playbookContext },
    });
    expect(leader.playbook_leader).toBe(true);
    await resumeSettledHuntPlaybooks(testContext);
    expect(resume).not.toHaveBeenCalled();
    // Never dispatched: expired without retry, the group is settled
    await expireHuntRun(testContext, await loadRun(leader.internal_id), 'Hunt manager test');
    expect(await resumeSettledHuntPlaybooks(testContext)).toBeGreaterThanOrEqual(1);
    expect(resume).toHaveBeenCalledTimes(1);
    expect(resume.mock.calls[0][2]).toMatchObject({ playbook_id: playbookContext.playbook_id, step_id: 'hunt-step', execution_id: executionId });
    const handedOver = await loadRun(leader.internal_id);
    expect(handedOver.playbook_resumed_at).toBeTruthy();
    // The continuation is handed over: the run no longer holds it
    expect(handedOver.playbook_leader).toBe(false);
    await resumeSettledHuntPlaybooks(testContext);
    expect(resume).toHaveBeenCalledTimes(1);
    resume.mockRestore();
  });

  it('should resume each entity of a playbook hunt step on its own runs, whatever the other entities of the step', async () => {
    const resume = vi.spyOn(playbookManager, 'playbookStepExecution').mockResolvedValue(true);
    const hunt = await loadHunt(huntId);
    const playbookId = uuidv4();
    const executionId = uuidv4();
    const startFor = async (instanceId: string) => {
      const bundle = JSON.stringify({ id: `bundle--${uuidv4()}`, type: 'bundle', objects: [] });
      const playbookContext = {
        playbook_id: playbookId,
        step_id: 'hunt-step',
        previous_step_id: 'entry-step',
        execution_id: executionId,
        event_id: 'event-id',
        data_instance_id: instanceId,
        execution_start: new Date().toISOString(),
        include_results: false,
        bundle,
        previous_bundle: bundle,
      };
      const [leader] = await createHuntRuns(testContext, hunt, {
        trigger: HUNT_RUN_TRIGGER_PLAYBOOK,
        dispatch: false,
        playbook: { playbookId, executionId, stepId: 'hunt-step', instanceId, context: playbookContext },
      });
      return leader;
    };
    const resumedInstances = () => resume.mock.calls
      .map((call) => call[2] as { execution_id: string; data_instance_id: string })
      .filter((input) => input.execution_id === executionId)
      .map((input) => input.data_instance_id);
    try {
      const firstInstance = `intrusion-set--${uuidv4()}`;
      const secondInstance = `intrusion-set--${uuidv4()}`;
      const first = await startFor(firstInstance);
      const second = await startFor(secondInstance);
      expect([first.playbook_leader, second.playbook_leader]).toEqual([true, true]);
      // The first entity resumes once its run is settled, although the run of the second one is still pending
      await expireHuntRun(testContext, await loadRun(first.internal_id), 'Hunt manager test');
      await resumeSettledHuntPlaybooks(testContext);
      expect(resumedInstances()).toEqual([firstInstance]);
      expect((await loadRun(second.internal_id)).playbook_resumed_at).toBeFalsy();
      // The second entity resumes on its own run only
      await expireHuntRun(testContext, await loadRun(second.internal_id), 'Hunt manager test');
      await resumeSettledHuntPlaybooks(testContext);
      expect(resumedInstances()).toEqual([firstInstance, secondInstance]);
    } finally {
      resume.mockRestore();
    }
  });

  it('should purge the translation previews past their retention', async () => {
    const hunt = await loadHunt(huntId);
    const [preview] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_PREVIEW, mode: HUNT_RUN_MODE_PREVIEW, dispatch: false });
    await expireHuntRun(testContext, preview, 'Hunt manager test');
    await purgeExpiredHuntRuns(testContext);
    expect(await loadRun(preview.internal_id)).toBeTruthy();
    const { previewRetentionDays } = HUNT_CONFIG;
    HUNT_CONFIG.previewRetentionDays = 0;
    try {
      expect(await purgeExpiredHuntRuns(testContext)).toBeGreaterThanOrEqual(1);
    } finally {
      HUNT_CONFIG.previewRetentionDays = previewRetentionDays;
    }
    expect(await loadRun(preview.internal_id)).toBeFalsy();
  });

  it('should keep racing dispatches of a connector within its budget and dispatch each run once', async () => {
    const hunt = await loadHunt(huntId);
    const runs: BasicStoreEntityHuntRun[] = [];
    for (let index = 0; index < 3; index += 1) {
      runs.push(...await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false }));
    }
    const occupied = (await listHuntRuns(huntId))
      .filter((run) => HUNT_RUN_ACTIVE_STATUSES.includes(run.hunt_run_status) && run.dispatched_at).length;
    const { maxConcurrentRunsPerConnector } = HUNT_CONFIG;
    HUNT_CONFIG.maxConcurrentRunsPerConnector = occupied + 1;
    try {
      const results = await Promise.all([...runs, runs[0]].map((run) => dispatchHuntRun(testContext, run, hunt)));
      expect(results.filter((dispatched) => dispatched)).toHaveLength(1);
      const reloaded = await Promise.all(runs.map((run) => loadRun(run.internal_id)));
      expect(reloaded.filter((run) => run.dispatched_at)).toHaveLength(1);
      expect(reloaded.filter((run) => run.work_id)).toHaveLength(1);
    } finally {
      HUNT_CONFIG.maxConcurrentRunsPerConnector = maxConcurrentRunsPerConnector;
    }
    for (let index = 0; index < runs.length; index += 1) {
      await expireHuntRun(testContext, await loadRun(runs[index].internal_id), 'Hunt manager test');
    }
  });

  it('should delete the work of a dispatch whose message cannot be published', async () => {
    const hunt = await loadHunt(huntId);
    const [run] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false });
    const { maxConcurrentRunsPerConnector } = HUNT_CONFIG;
    HUNT_CONFIG.maxConcurrentRunsPerConnector = 1000;
    const createWork = vi.spyOn(workDomain, 'createWork');
    const push = vi.spyOn(rabbitmq, 'pushToConnector').mockRejectedValueOnce(new Error('Queue unavailable'));
    try {
      await expect(dispatchHuntRun(testContext, run, hunt)).rejects.toThrow('Queue unavailable');
      const work = await createWork.mock.results[0].value;
      expect(work?.id).toBeTruthy();
      expect(await workDomain.loadWorkById(testContext, ADMIN_USER, work.id)).toBeFalsy();
      // The run stays queued for the next dispatch, its budget slot released
      const released = await loadRun(run.internal_id);
      expect(released.dispatched_at).toBeFalsy();
      expect(released.work_id).toBeFalsy();
    } finally {
      HUNT_CONFIG.maxConcurrentRunsPerConnector = maxConcurrentRunsPerConnector;
      createWork.mockRestore();
      push.mockRestore();
      await expireHuntRun(testContext, await loadRun(run.internal_id), 'Hunt manager test');
    }
  });

  it('should link a run to its work before its message is published', async () => {
    const hunt = await loadHunt(huntId);
    const [run] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false });
    const { maxConcurrentRunsPerConnector } = HUNT_CONFIG;
    HUNT_CONFIG.maxConcurrentRunsPerConnector = 1000;
    const linkedAtPublish: { stored?: string | null; sent?: string } = {};
    const push = vi.spyOn(rabbitmq, 'pushToConnector').mockImplementationOnce(async (_connectorId, message) => {
      linkedAtPublish.stored = (await loadRun(run.internal_id)).work_id;
      linkedAtPublish.sent = (message as { internal: { work_id: string } }).internal.work_id;
      return true as never;
    });
    try {
      await expect(dispatchHuntRun(testContext, run, hunt)).resolves.toBe(true);
      // The first report of the connector finds the work it was sent
      expect(linkedAtPublish.stored).toBeTruthy();
      expect(linkedAtPublish.stored).toEqual(linkedAtPublish.sent);
    } finally {
      HUNT_CONFIG.maxConcurrentRunsPerConnector = maxConcurrentRunsPerConnector;
      push.mockRestore();
      await expireHuntRun(testContext, await loadRun(run.internal_id), 'Hunt manager test');
    }
  });

  it('should publish a run whose publication date was not recorded again under the work of its first publication', async () => {
    const hunt = await loadHunt(huntId);
    const [run] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false });
    const { maxConcurrentRunsPerConnector } = HUNT_CONFIG;
    HUNT_CONFIG.maxConcurrentRunsPerConnector = 1000;
    const sent: string[] = [];
    const push = vi.spyOn(rabbitmq, 'pushToConnector').mockImplementation(async (_connectorId, message) => {
      sent.push((message as { internal: { work_id: string } }).internal.work_id);
      return true as never;
    });
    const createWork = vi.spyOn(workDomain, 'createWork');
    try {
      await expect(dispatchHuntRun(testContext, run, hunt)).resolves.toBe(true);
      const first = await loadRun(run.internal_id);
      // The publication happened but its date was never stored, and the grace of a dispatch in progress is over
      await patchAttribute(testContext, ADMIN_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { published_at: null, dispatched_at: hoursAgo(2) });
      expect(await requeueUnpublishedHuntRuns(testContext)).toBeGreaterThanOrEqual(1);
      const released = await loadRun(run.internal_id);
      expect(released.dispatched_at).toBeFalsy();
      expect(released.work_id).toEqual(first.work_id);
      expect(await workDomain.loadWorkById(testContext, ADMIN_USER, first.work_id as string)).toBeTruthy();
      await expect(dispatchHuntRun(testContext, released, hunt)).resolves.toBe(true);
      // Both messages carry the same work: the report of whichever reaches the connector is bound to the run
      expect(sent).toEqual([first.work_id, first.work_id]);
      expect(createWork).toHaveBeenCalledTimes(1);
      expect((await loadRun(run.internal_id)).work_id).toEqual(first.work_id);
    } finally {
      HUNT_CONFIG.maxConcurrentRunsPerConnector = maxConcurrentRunsPerConnector;
      push.mockRestore();
      createWork.mockRestore();
      await expireHuntRun(testContext, await loadRun(run.internal_id), 'Hunt manager test');
    }
  });

  it('should replace the planned automatic retry of a run by a manual retry, as its next attempt', async () => {
    const hunt = await loadHunt(huntId);
    const [run] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false });
    await patchAttribute(testContext, ADMIN_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { dispatched_at: hoursAgo(2) });
    await expireHuntRun(testContext, await loadRun(run.internal_id), 'Hunt manager test');
    const expired = await loadRun(run.internal_id);
    expect(expired.next_retry_at).toBeTruthy();
    const replacement = await retryHuntRun(testContext, ADMIN_USER, run.internal_id);
    expect(replacement.attempt).toEqual((expired.attempt ?? 1) + 1);
    expect(replacement.hunt_run_trigger).toEqual(HUNT_RUN_TRIGGER_RETRY);
    expect((await loadRun(run.internal_id)).next_retry_at).toBeFalsy();
    const retries = () => listHuntRuns(huntId).then((list) => list.filter((item) => item.hunt_run_trigger === HUNT_RUN_TRIGGER_RETRY).length);
    const retriesAfterManual = await retries();
    await retryFailedHuntRuns(testContext);
    expect(await retries()).toEqual(retriesAfterManual);
    // A later retry of the same run gets its replacement back instead of a second next attempt
    expect((await retryHuntRun(testContext, ADMIN_USER, run.internal_id)).internal_id).toEqual(replacement.internal_id);
    await expireHuntRun(testContext, await loadRun(replacement.internal_id), 'Hunt manager test');
  });

  it('should create a single next attempt for concurrent retries of a run', async () => {
    const hunt = await loadHunt(huntId);
    const [run] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false });
    await patchAttribute(testContext, ADMIN_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { dispatched_at: hoursAgo(2) });
    await expireHuntRun(testContext, await loadRun(run.internal_id), 'Hunt manager test');
    const expired = await loadRun(run.internal_id);
    // Two manual retries and the hunt manager, all at once
    await patchAttribute(testContext, ADMIN_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { next_retry_at: hoursAgo(1) });
    const [first, second] = await Promise.all([
      retryHuntRun(testContext, ADMIN_USER, run.internal_id),
      retryHuntRun(testContext, ADMIN_USER, run.internal_id),
      retryFailedHuntRuns(testContext),
    ]);
    expect(first.internal_id).toEqual(second.internal_id);
    const nextAttempts = (await middlewareLoader.fullEntitiesList<BasicStoreEntityHuntRun>(testContext, ADMIN_USER, [ENTITY_TYPE_HUNT_RUN], {
      filters: { mode: FilterMode.And, filters: [{ key: ['hunt_id'], values: [huntId] }, { key: ['hunt_run_trigger'], values: [HUNT_RUN_TRIGGER_RETRY] }], filterGroups: [] },
      noFiltersChecking: true,
    })).filter((item) => item.attempt === (expired.attempt ?? 1) + 1 && item.time_window_start === expired.time_window_start);
    expect(nextAttempts.map((item) => item.internal_id)).toEqual([first.internal_id]);
    expect((await loadRun(run.internal_id)).next_retry_at).toBeFalsy();
    await expireHuntRun(testContext, await loadRun(first.internal_id), 'Hunt manager test');
  });

  it('should give its own next attempt to each run sharing the hunt, connector, window and attempt of another', async () => {
    const hunt = await loadHunt(huntId);
    const window = { windowStart: hoursAgo(6), windowEnd: hoursAgo(5) };
    const [first] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false, ...window });
    const [second] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false, ...window });
    const runs = [first, second];
    for (let index = 0; index < runs.length; index += 1) {
      await patchAttribute(testContext, ADMIN_USER, runs[index].internal_id, ENTITY_TYPE_HUNT_RUN, { dispatched_at: hoursAgo(2) });
      await expireHuntRun(testContext, await loadRun(runs[index].internal_id), 'Hunt manager test');
    }
    const firstReplacement = await retryHuntRun(testContext, ADMIN_USER, first.internal_id);
    const secondReplacement = await retryHuntRun(testContext, ADMIN_USER, second.internal_id);
    expect(secondReplacement.internal_id).not.toEqual(firstReplacement.internal_id);
    expect(firstReplacement.retry_of).toEqual(first.internal_id);
    expect(secondReplacement.retry_of).toEqual(second.internal_id);
    // The planned retry of the second run is consumed by its own replacement, not by the one of the first run
    expect((await loadRun(second.internal_id)).next_retry_at).toBeFalsy();
    await expireHuntRun(testContext, await loadRun(firstReplacement.internal_id), 'Hunt manager test');
    await expireHuntRun(testContext, await loadRun(secondReplacement.internal_id), 'Hunt manager test');
  });

  it('should paginate the readable results of a run and count only them', async () => {
    const hunt = await loadHunt(huntId);
    const [run] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false });
    const missing = 'indicator--4b1f1a2e-8f2c-4c1e-9d5b-0a6c2f9e7d31';
    await patchAttribute(testContext, ADMIN_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { result_ids: [intrusionSetId, missing, securityPlatformId] });
    const recorded = await loadRun(run.internal_id);
    const findByIds = vi.spyOn(middlewareLoader, 'internalFindByIds');
    const firstPage = await findHuntRunResults(testContext, ADMIN_USER, recorded, 1);
    // Access is resolved over the identifiers of every recorded result, and only the objects of the page are loaded
    expect(findByIds.mock.calls.map(([, , ids, args]) => [ids, args?.baseData === true])).toEqual([
      [[intrusionSetId, missing, securityPlatformId], true],
      [[intrusionSetId], false],
    ]);
    findByIds.mockRestore();
    expect(firstPage.pageInfo).toMatchObject({ globalCount: 2, hasNextPage: true, hasPreviousPage: false });
    expect(firstPage.edges.map((edge) => edge.node.internal_id)).toEqual([intrusionSetId]);
    const secondPage = await findHuntRunResults(testContext, ADMIN_USER, recorded, 1, firstPage.pageInfo.endCursor);
    expect(secondPage.edges.map((edge) => edge.node.internal_id)).toEqual([securityPlatformId]);
    expect(secondPage.pageInfo).toMatchObject({ globalCount: 2, hasNextPage: false, hasPreviousPage: true });
    // A cursor that is not a readable result never restarts the pagination
    await expect(findHuntRunResults(testContext, ADMIN_USER, recorded, 1, missing)).rejects.toThrow('The cursor is not a result of this run you can read');
    expect(await findHuntRunResultIds(testContext, ADMIN_USER, recorded)).toEqual([intrusionSetId, securityPlatformId]);
    await expireHuntRun(testContext, recorded, 'Hunt manager test');
  });

  it('should give a playbook the results of a run as its hunt connector can read them', async () => {
    const hunt = await loadHunt(huntId);
    const [run] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false });
    const load = vi.spyOn(middleware, 'stixLoadByIds');
    try {
      await patchAttribute(testContext, ADMIN_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { connector_id: CONNECTOR_ID, result_ids: [intrusionSetId, securityPlatformId] });
      // An object already in the bundle is not loaded again
      const results = await loadHuntRunResultsForPlaybook(testContext, [await loadRun(run.internal_id)], new Set([securityPlatformId]));
      // Loaded with the user of the hunt connector of the run, never with the automation identity of the playbook
      expect(load).toHaveBeenCalledTimes(1);
      expect(load.mock.calls[0][1].user_email).toEqual(USER_CONNECTOR.email);
      expect(load.mock.calls[0][2]).toEqual([intrusionSetId]);
      expect(results.map((result) => result.extensions[STIX_EXT_OCTI].id)).toEqual([intrusionSetId]);
      // A run without a hunt connector gives the playbook nothing
      await patchAttribute(testContext, ADMIN_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { connector_id: null });
      expect(await loadHuntRunResultsForPlaybook(testContext, [await loadRun(run.internal_id)], new Set())).toEqual([]);
      expect(load).toHaveBeenCalledTimes(1);
    } finally {
      load.mockRestore();
      await expireHuntRun(testContext, await loadRun(run.internal_id), 'Hunt manager test');
    }
  });

  it('should refuse to execute a hunt whose logic was cleared while paused', async () => {
    const before = await loadHunt(huntId);
    await patchAttribute(testContext, ADMIN_USER, huntId, ENTITY_TYPE_HUNT, { hunt_status: 'paused', sigma_rule: '', native_queries: [] });
    try {
      await expect(createHuntRuns(testContext, await loadHunt(huntId), { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false }))
        .rejects.toThrow('Add a Sigma rule or a native query');
    } finally {
      await patchAttribute(testContext, ADMIN_USER, huntId, ENTITY_TYPE_HUNT, {
        hunt_status: before.hunt_status,
        sigma_rule: before.sigma_rule,
        native_queries: before.native_queries,
      });
    }
  });

  const addTestHunt = async (name: string) => {
    const created = await queryAsAdminWithSuccess({
      query: gql`mutation HuntAdd($input: HuntAddInput!) { huntAdd(input: $input) { id } }`,
      variables: {
        input: {
          name,
          sigma_rule: SIGMA_RULE,
          huntTargets: [intrusionSetId],
          native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr CommandLine="* -enc *"' }],
        },
      },
    });
    return created.data?.huntAdd.id as string;
  };

  const deleteTestHunt = async (id: string) => {
    const runs = await listHuntRuns(id);
    for (let index = 0; index < runs.length; index += 1) {
      await deleteElementById(testContext, ADMIN_USER, runs[index].internal_id, ENTITY_TYPE_HUNT_RUN);
    }
    await queryAsAdmin({ query: gql`mutation HuntDelete($id: ID!) { huntDelete(id: $id) }`, variables: { id } });
  };

  it('should evaluate every PIR activated hunt at each tick, past the first page', async () => {
    const olderId = await addTestHunt('Hunt manager test older PIR hunt');
    const newerId = await addTestHunt('Hunt manager test newer PIR hunt');
    await patchAttribute(testContext, ADMIN_USER, olderId, ENTITY_TYPE_HUNT, { hunt_pir_activation: true });
    await patchAttribute(testContext, ADMIN_USER, newerId, ENTITY_TYPE_HUNT, { hunt_pir_activation: true });
    const criterion = { weight: 1, filters: { mode: FilterMode.And, filters: [{ key: ['entity_type'], values: [ENTITY_TYPE_INTRUSION_SET] }], filterGroups: [] } };
    const pir = await pirAdd(testContext, ADMIN_USER, {
      name: 'Hunt manager test paging PIR',
      pir_type: PirType.ThreatLandscape,
      pir_rescan_days: 0,
      pir_filters: { mode: FilterMode.And, filters: [], filterGroups: [] },
      pir_criteria: [criterion],
    });
    const flag = { relationshipId: uuidv4(), sourceId: intrusionSetId };
    const { automationPageSize } = HUNT_CONFIG;
    // One hunt per page: a single first page would read the same oldest hunt at every tick
    HUNT_CONFIG.automationPageSize = 1;
    try {
      await pirFlagElement(testContext, ADMIN_USER, pir.standard_id, { ...flag, matchingCriteria: [criterion] });
      await reconcilePirActivatedHunts(testContext);
      expect((await loadHunt(olderId)).hunt_pir_armed).toBe(true);
      expect((await loadHunt(newerId)).hunt_pir_armed).toBe(true);
    } finally {
      HUNT_CONFIG.automationPageSize = automationPageSize;
      await pirUnflagElement(testContext, ADMIN_USER, pir.standard_id, flag);
      await deletePir(testContext, ADMIN_USER, pir.id);
      await deleteTestHunt(olderId);
      await deleteTestHunt(newerId);
    }
  });

  it('should keep the due occurrence of the scheduled hunts beyond the tick budget', async () => {
    const firstId = await addTestHunt('Hunt manager test first due cron hunt');
    const secondId = await addTestHunt('Hunt manager test second due cron hunt');
    await patchAttribute(testContext, ADMIN_USER, firstId, ENTITY_TYPE_HUNT, { hunt_schedule: '0 */6 * * *', next_run_at: hoursAgo(3) });
    await patchAttribute(testContext, ADMIN_USER, secondId, ENTITY_TYPE_HUNT, { hunt_schedule: '0 */6 * * *', next_run_at: hoursAgo(2) });
    const { maxRunsPerTick } = HUNT_CONFIG;
    HUNT_CONFIG.maxRunsPerTick = 1;
    try {
      await runScheduledHunts(testContext);
      expect(new Date((await loadHunt(firstId)).next_run_at as string).getTime()).toBeGreaterThan(Date.now());
      // Beyond the budget: the occurrence is still due, not skipped
      expect(new Date((await loadHunt(secondId)).next_run_at as string).getTime()).toBeLessThan(Date.now());
      expect((await listHuntRuns(secondId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_SCHEDULE)).toHaveLength(0);
      await runScheduledHunts(testContext);
      expect((await listHuntRuns(secondId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_SCHEDULE)).toHaveLength(1);
    } finally {
      HUNT_CONFIG.maxRunsPerTick = maxRunsPerTick;
      await deleteTestHunt(firstId);
      await deleteTestHunt(secondId);
    }
  });

  it('should queue the scheduled run of a hunt connector temporarily offline instead of losing the occurrence', async () => {
    const offlineId = await addTestHunt('Hunt manager test offline connector hunt');
    const { completeConnector } = repository;
    const offline = vi.spyOn(repository, 'completeConnector').mockImplementation((connector) => {
      const completed = completeConnector(connector);
      return completed?.internal_id === CONNECTOR_ID ? { ...completed, active: false } : completed;
    });
    try {
      await patchAttribute(testContext, ADMIN_USER, offlineId, ENTITY_TYPE_HUNT, { hunt_schedule: '0 */6 * * *', next_run_at: hoursAgo(1) });
      // A manual run expects an answer now: it only targets the connectors that are online
      expect(await createHuntRuns(testContext, await loadHunt(offlineId), { trigger: HUNT_RUN_TRIGGER_MANUAL })).toHaveLength(0);
      // The scheduled run waits queued for the connector, dispatched once it is back or expired past the queue expiry
      await runScheduledHunts(testContext);
      const scheduled = (await listHuntRuns(offlineId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_SCHEDULE);
      expect(scheduled).toHaveLength(1);
      expect(scheduled[0].connector_id).toEqual(CONNECTOR_ID);
      expect(scheduled[0].hunt_run_status).toEqual(HUNT_RUN_STATUS_QUEUED);
      expect(scheduled[0].dispatched_at).toBeFalsy();
      expect(new Date((await loadHunt(offlineId)).next_run_at as string).getTime()).toBeGreaterThan(Date.now());
    } finally {
      offline.mockRestore();
      await deleteTestHunt(offlineId);
    }
  });

  it('should keep the due occurrence of a scheduled hunt whose runs could not be created', async () => {
    const transientId = await addTestHunt('Hunt manager test transient failure hunt');
    const { createEntity } = middleware;
    const failing = vi.spyOn(middleware, 'createEntity').mockImplementation((context, user, input, type, opts) => (
      type === ENTITY_TYPE_HUNT_RUN && input.hunt_id === transientId
        ? Promise.reject(new Error('Hunt manager test engine unavailable'))
        : createEntity(context, user, input, type, opts)
    ));
    try {
      await patchAttribute(testContext, ADMIN_USER, transientId, ENTITY_TYPE_HUNT, { hunt_schedule: '0 */6 * * *', next_run_at: hoursAgo(1) });
      await runScheduledHunts(testContext);
      expect(new Date((await loadHunt(transientId)).next_run_at as string).getTime()).toBeLessThan(Date.now());
      failing.mockRestore();
      await runScheduledHunts(testContext);
      expect((await listHuntRuns(transientId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_SCHEDULE)).toHaveLength(1);
      expect(new Date((await loadHunt(transientId)).next_run_at as string).getTime()).toBeGreaterThan(Date.now());
    } finally {
      failing.mockRestore();
      await deleteTestHunt(transientId);
    }
  });

  it('should arm a PIR activated hunt only once its arming run started', async () => {
    const armedId = await addTestHunt('Hunt manager test arming run hunt');
    await patchAttribute(testContext, ADMIN_USER, armedId, ENTITY_TYPE_HUNT, { hunt_pir_activation: true });
    const criterion = { weight: 1, filters: { mode: FilterMode.And, filters: [{ key: ['entity_type'], values: [ENTITY_TYPE_INTRUSION_SET] }], filterGroups: [] } };
    const pir = await pirAdd(testContext, ADMIN_USER, {
      name: 'Hunt manager test arming PIR',
      pir_type: PirType.ThreatLandscape,
      pir_rescan_days: 0,
      pir_filters: { mode: FilterMode.And, filters: [], filterGroups: [] },
      pir_criteria: [criterion],
    });
    const flag = { relationshipId: uuidv4(), sourceId: intrusionSetId };
    const { maxRunsPerTick } = HUNT_CONFIG;
    try {
      await pirFlagElement(testContext, ADMIN_USER, pir.standard_id, { ...flag, matchingCriteria: [criterion] });
      // No run can start in this tick: the hunt stays disarmed and arming is tried again
      HUNT_CONFIG.maxRunsPerTick = 0;
      await reconcilePirActivatedHunts(testContext);
      expect((await loadHunt(armedId)).hunt_pir_armed).not.toBe(true);
      HUNT_CONFIG.maxRunsPerTick = maxRunsPerTick;
      await reconcilePirActivatedHunts(testContext);
      expect((await loadHunt(armedId)).hunt_pir_armed).toBe(true);
      const armingRuns = await listHuntRuns(armedId);
      expect(armingRuns.filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_PIR)).toHaveLength(1);
      expect(armingRuns.filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_STANDING)).toHaveLength(0);
    } finally {
      HUNT_CONFIG.maxRunsPerTick = maxRunsPerTick;
      await pirUnflagElement(testContext, ADMIN_USER, pir.standard_id, flag);
      await deletePir(testContext, ADMIN_USER, pir.id);
      await deleteTestHunt(armedId);
    }
  });

  it('should keep a standing trigger pending until a tick serves it', async () => {
    const standingId = await addTestHunt('Hunt manager test pending standing hunt');
    // A trigger raised by an earlier tick and not served yet
    await patchAttribute(testContext, ADMIN_USER, standingId, ENTITY_TYPE_HUNT, { hunt_schedule: 'standing', next_run_at: hoursAgo(1) });
    await redisSetManagerEventState(HUNT_MANAGER_STREAM_STATE, `${Date.now()}-0`);
    const { maxRunsPerTick } = HUNT_CONFIG;
    try {
      HUNT_CONFIG.maxRunsPerTick = 0;
      await processStandingHunts(testContext);
      expect((await loadHunt(standingId)).next_run_at).toBeTruthy();
      expect(await listHuntRuns(standingId)).toHaveLength(0);
      HUNT_CONFIG.maxRunsPerTick = maxRunsPerTick;
      expect(await processStandingHunts(testContext)).toBeGreaterThanOrEqual(1);
      expect((await loadHunt(standingId)).next_run_at).toBeFalsy();
      expect((await listHuntRuns(standingId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_STANDING)).toHaveLength(1);
    } finally {
      HUNT_CONFIG.maxRunsPerTick = maxRunsPerTick;
      await deleteTestHunt(standingId);
    }
  });

  it('should dispatch the runs of a healthy connector past the runs waiting on a saturated one', async () => {
    const sentinelConnectorId = uuidv4();
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: gql`mutation RegisterConnector($input: RegisterConnectorInput) { registerConnector(input: $input) { id } }`,
      variables: { input: { id: sentinelConnectorId, name: 'Hunt manager test Sentinel connector', type: 'INTERNAL_HUNT', scope: ['microsoft-sentinel'], auto: false, only_contextual: false } },
    });
    const registration = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: gql`mutation HuntConnectorRegister($input: HuntConnectorRegisterInput!) {
        huntConnectorRegister(input: $input) { id securityPlatform { id } }
      }`,
      variables: { input: { connector_id: sentinelConnectorId, platform: 'microsoft-sentinel', languages: ['kql'], security_platform_name: 'Hunt manager test Sentinel' } },
    });
    const sentinelPlatformId = registration.data?.huntConnectorRegister.securityPlatform.id;
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    const saturatedHunt = await loadHunt(huntId);
    const sentinelHuntId = await addTestHunt('Hunt manager test Sentinel hunt');
    await patchAttribute(testContext, ADMIN_USER, sentinelHuntId, ENTITY_TYPE_HUNT, {
      native_queries: [{ platform: 'microsoft-sentinel', language: 'kql', query: 'DeviceProcessEvents | take 1', pipeline: null }],
    });
    const { maxRunsPerTick, maxConcurrentRunsPerConnector } = HUNT_CONFIG;
    const waiting: BasicStoreEntityHuntRun[] = [];
    try {
      // Runs left queued by earlier tests are dispatched first, so that only the runs below compete
      await dispatchQueuedHuntRuns(testContext);
      // The Splunk connector runs one hunt and takes no other run
      waiting.push(...await createHuntRuns(testContext, saturatedHunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, securityPlatformIds: [securityPlatformId] }));
      const occupied = (await listHuntRuns(huntId)).filter((run) => HUNT_RUN_ACTIVE_STATUSES.includes(run.hunt_run_status) && run.dispatched_at).length;
      expect(occupied).toBeGreaterThanOrEqual(1);
      HUNT_CONFIG.maxConcurrentRunsPerConnector = occupied;
      for (let index = 0; index < 3; index += 1) {
        waiting.push(...await createHuntRuns(testContext, saturatedHunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false, securityPlatformIds: [securityPlatformId] }));
      }
      const sentinelHunt = await loadHunt(sentinelHuntId);
      const [healthy] = await createHuntRuns(testContext, sentinelHunt, { trigger: HUNT_RUN_TRIGGER_MANUAL, dispatch: false, securityPlatformIds: [sentinelPlatformId] });
      expect(healthy.connector_id).toEqual(sentinelConnectorId);
      // One tick reads fewer runs than wait on the saturated connector, all of them older than the healthy one
      HUNT_CONFIG.maxRunsPerTick = 2;
      expect(await dispatchQueuedHuntRuns(testContext)).toEqual(1);
      expect((await loadRun(healthy.internal_id)).dispatched_at).toBeTruthy();
    } finally {
      HUNT_CONFIG.maxRunsPerTick = maxRunsPerTick;
      HUNT_CONFIG.maxConcurrentRunsPerConnector = maxConcurrentRunsPerConnector;
      for (let index = 0; index < waiting.length; index += 1) {
        await deleteElementById(testContext, ADMIN_USER, waiting[index].internal_id, ENTITY_TYPE_HUNT_RUN);
      }
      await deleteTestHunt(sentinelHuntId);
      await queryAsAdmin({ query: gql`mutation DeleteConnector($id: ID!) { deleteConnector(id: $id) }`, variables: { id: sentinelConnectorId } });
      if (sentinelPlatformId) {
        await deleteElementById(testContext, ADMIN_USER, sentinelPlatformId, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
      }
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    }
  });

  it('should start the runs of a hunt once when a playbook step races on the same entity within the debounce window', async () => {
    const resume = vi.spyOn(playbookManager, 'playbookStepExecution').mockResolvedValue(true);
    const raceHuntId = await addTestHunt('Hunt manager test playbook race hunt');
    const racePlaybookId = uuidv4();
    const elementNamed = (name: string) => ({ id: `intrusion-set--${uuidv4()}`, type: 'intrusion-set', spec_version: '2.1', name });
    const notify = PLAYBOOK_HUNT_COMPONENT.notify as NonNullable<typeof PLAYBOOK_HUNT_COMPONENT.notify>;
    const execute = (executionId: string, element: { id: string }, playbookId = racePlaybookId) => {
      const bundle = { id: `bundle--${uuidv4()}`, type: 'bundle', spec_version: '2.1', objects: [element] };
      return notify({
        executionId,
        eventId: 'event-id',
        playbookId,
        dataInstanceId: element.id,
        previousPlaybookNodeId: 'entry-step',
        playbookNode: {
          id: 'hunt-step',
          name: 'Run hunts',
          component_id: PLAYBOOK_HUNT_COMPONENT.id,
          configuration: {
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
            hunt_ids: [raceHuntId],
            security_platform_ids: [],
            time_window_hours: 0,
            max_hunts: 10,
            wait_for_results: false,
            include_results: false,
          },
        },
        bundle,
        previousStepBundle: bundle,
      } as unknown as Parameters<typeof notify>[0]);
    };
    const playbookRuns = async () => (await listHuntRuns(raceHuntId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_PLAYBOOK);
    try {
      const element = elementNamed('Hunt manager test race element');
      await Promise.all([execute(uuidv4(), element), execute(uuidv4(), element)]);
      const runs = await playbookRuns();
      expect(runs.length).toBeGreaterThan(0);
      expect(new Set(runs.map((run) => run.playbook_execution_id)).size).toEqual(1);
      expect(runs.every((run) => run.playbook_instance_id === element.id)).toBe(true);
      // Both executions continue: the one that ran the hunt and the one the debounce skipped
      expect(resume).toHaveBeenCalledTimes(2);
      // The same step on another entity, and another playbook on the same entity, are not skipped
      const otherExecutionId = uuidv4();
      const otherPlaybookExecutionId = uuidv4();
      await execute(otherExecutionId, elementNamed('Hunt manager test other race element'));
      await execute(otherPlaybookExecutionId, element, uuidv4());
      const executions = new Set((await playbookRuns()).map((run) => run.playbook_execution_id));
      expect(executions.has(otherExecutionId)).toBe(true);
      expect(executions.has(otherPlaybookExecutionId)).toBe(true);
    } finally {
      resume.mockRestore();
      await deleteTestHunt(raceHuntId);
    }
  });

  it('should hand the continuation of a playbook hunt step over only once the runs of every hunt exist', async () => {
    const resume = vi.spyOn(playbookManager, 'playbookStepExecution').mockResolvedValue(true);
    const firstHuntId = await addTestHunt('Hunt manager test continuation first hunt');
    const secondHuntId = await addTestHunt('Hunt manager test continuation second hunt');
    const executionId = uuidv4();
    const element = { id: `intrusion-set--${uuidv4()}`, type: 'intrusion-set', spec_version: '2.1', name: 'Hunt manager test continuation element' };
    const group = () => findPlaybookHuntRuns(testContext, { executionId, instanceId: element.id, stepId: 'hunt-step' });
    // Before the runs of each hunt are created, no run of the step holds the continuation yet
    const leadersBeforeEachHunt: number[] = [];
    const createRuns = huntRunDomain.createHuntRuns;
    const create = vi.spyOn(huntRunDomain, 'createHuntRuns').mockImplementation(async (...args) => {
      leadersBeforeEachHunt.push((await group()).filter((run) => run.playbook_leader).length);
      return createRuns(...args);
    });
    const notify = PLAYBOOK_HUNT_COMPONENT.notify as NonNullable<typeof PLAYBOOK_HUNT_COMPONENT.notify>;
    const bundle = { id: `bundle--${uuidv4()}`, type: 'bundle', spec_version: '2.1', objects: [element] };
    try {
      await notify({
        executionId,
        eventId: 'event-id',
        playbookId: uuidv4(),
        dataInstanceId: element.id,
        previousPlaybookNodeId: 'entry-step',
        playbookNode: {
          id: 'hunt-step',
          name: 'Run hunts',
          component_id: PLAYBOOK_HUNT_COMPONENT.id,
          configuration: {
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
            hunt_ids: [firstHuntId, secondHuntId],
            security_platform_ids: [],
            time_window_hours: 0,
            max_hunts: 10,
            wait_for_results: true,
            include_results: false,
          },
        },
        bundle,
        previousStepBundle: bundle,
      } as unknown as Parameters<typeof notify>[0]);
      expect(leadersBeforeEachHunt).toEqual([0, 0]);
      const runs = await group();
      expect(new Set(runs.map((run) => run.hunt_id))).toEqual(new Set([firstHuntId, secondHuntId]));
      expect(runs.filter((run) => run.playbook_leader)).toHaveLength(1);
      expect(resume).not.toHaveBeenCalled();
    } finally {
      create.mockRestore();
      resume.mockRestore();
      await deleteTestHunt(firstHuntId);
      await deleteTestHunt(secondHuntId);
    }
  });
});
