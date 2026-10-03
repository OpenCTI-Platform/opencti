import gql from 'graphql-tag';
import { v4 as uuidv4 } from 'uuid';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, testContext, USER_CONNECTOR } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { deleteElementById, patchAttribute } from '../../../src/database/middleware';
import * as middlewareLoader from '../../../src/database/middleware-loader';
import { resetCacheForEntity } from '../../../src/database/cache';
import * as playbookManager from '../../../src/manager/playbookManager/playbookManager';
import { FilterMode, OrderingMode } from '../../../src/generated/graphql';
import { ENTITY_TYPE_CONNECTOR } from '../../../src/schema/internalObject';
import { RELATION_IN_PIR } from '../../../src/schema/internalRelationship';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../src/modules/securityPlatform/securityPlatform-types';
import { type BasicStoreEntityHunt, ENTITY_TYPE_HUNT } from '../../../src/modules/hunt/hunt-types';
import {
  type BasicStoreEntityHuntRun,
  ENTITY_TYPE_HUNT_RUN,
  HUNT_RUN_MODE_PREVIEW,
  HUNT_RUN_STATUS_TIMEOUT,
  HUNT_RUN_TRIGGER_MANUAL,
  HUNT_RUN_TRIGGER_PLAYBOOK,
  HUNT_RUN_TRIGGER_PREVIEW,
  HUNT_RUN_TRIGGER_RETRY,
  HUNT_RUN_TRIGGER_SCHEDULE,
  HUNT_RUN_TRIGGER_STANDING,
} from '../../../src/modules/hunt/huntRun/huntRun-types';
import { createHuntRuns, expireHuntRun } from '../../../src/modules/hunt/huntRun/huntRun-domain';
import {
  dispatchQueuedHuntRuns,
  expireStaleHuntRuns,
  purgeExpiredHuntRuns,
  reconcilePirActivatedHunts,
  resumeSettledHuntPlaybooks,
  retryFailedHuntRuns,
  runScheduledHunts,
} from '../../../src/modules/hunt/hunt-automation';

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
    const { fullRelationsList } = middlewareLoader;
    const spy = vi.spyOn(middlewareLoader, 'fullRelationsList').mockImplementation((async (context, user, type, args) => {
      if (type === RELATION_IN_PIR) {
        return [{ fromId: intrusionSetId, toId: uuidv4(), relationship_type: RELATION_IN_PIR }];
      }
      return fullRelationsList(context, user, type, args);
    }) as typeof fullRelationsList);
    expect(await reconcilePirActivatedHunts(testContext)).toBeGreaterThanOrEqual(1);
    const armed = await loadHunt(huntId);
    expect(armed.hunt_pir_armed).toBe(true);
    expect(armed.hunt_pir_armed_at).toBeTruthy();
    expect(armed.hunt_status).toEqual('active');
    expect((await listHuntRuns(huntId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_STANDING)).toHaveLength(1);
    // Still flagged: no new run
    await reconcilePirActivatedHunts(testContext);
    expect((await listHuntRuns(huntId)).filter((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_STANDING)).toHaveLength(1);
    spy.mockRestore();
    await reconcilePirActivatedHunts(testContext);
    const disarmed = await loadHunt(huntId);
    expect(disarmed.hunt_pir_armed).toBe(false);
    expect(disarmed.hunt_status).toEqual('active');
    await patchAttribute(testContext, ADMIN_USER, huntId, ENTITY_TYPE_HUNT, { hunt_pir_activation: false });
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
    expect((await loadRun(leader.internal_id)).playbook_resumed_at).toBeTruthy();
    await resumeSettledHuntPlaybooks(testContext);
    expect(resume).toHaveBeenCalledTimes(1);
    resume.mockRestore();
  });

  it('should purge the translation previews past their retention', async () => {
    const hunt = await loadHunt(huntId);
    const [preview] = await createHuntRuns(testContext, hunt, { trigger: HUNT_RUN_TRIGGER_PREVIEW, mode: HUNT_RUN_MODE_PREVIEW, dispatch: false });
    await expireHuntRun(testContext, preview, 'Hunt manager test');
    await purgeExpiredHuntRuns(testContext);
    expect(await loadRun(preview.internal_id)).toBeTruthy();
    await patchAttribute(testContext, ADMIN_USER, preview.internal_id, ENTITY_TYPE_HUNT_RUN, { created_at: hoursAgo(8 * 24) });
    expect(await purgeExpiredHuntRuns(testContext)).toBeGreaterThanOrEqual(1);
    expect(await loadRun(preview.internal_id)).toBeFalsy();
  });
});
