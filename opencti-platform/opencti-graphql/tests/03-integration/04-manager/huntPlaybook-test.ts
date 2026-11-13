import gql from 'graphql-tag';
import { v4 as uuidv4 } from 'uuid';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, getAuthUser, queryInitPlatformAsTokenBearer, testContext } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsAuthUser } from '../../utils/testQueryHelper';
import { deleteElementById } from '../../../src/database/middleware';
import { fullEntitiesList, internalLoadById, topEntitiesList } from '../../../src/database/middleware-loader';
import { resetCacheForEntity } from '../../../src/database/cache';
import { wait } from '../../../src/database/utils';
import * as playbookManager from '../../../src/manager/playbookManager/playbookManager';
import * as enterpriseEdition from '../../../src/enterprise-edition/ee';
import { FilterMode } from '../../../src/generated/graphql';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import type { BasicStoreEntity } from '../../../src/types/store';
import { ENTITY_TYPE_INTRUSION_SET } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../src/modules/securityPlatform/securityPlatform-types';
import { type BasicStoreEntityHunt, ENTITY_TYPE_HUNT } from '../../../src/modules/hunt/hunt-types';
import { type BasicStoreEntityHuntRun, ENTITY_TYPE_HUNT_RUN, HUNT_RUN_TRIGGER_PLAYBOOK } from '../../../src/modules/hunt/huntRun/huntRun-types';
import { PLAYBOOK_HUNT_COMPONENT, PLAYBOOK_HUNT_SOURCE_DERIVED, PLAYBOOK_HUNT_SOURCE_EXISTING } from '../../../src/modules/playbook/components/hunt-component';
import { PLAYBOOK_HUNT_RESULT_FILTER } from '../../../src/modules/playbook/components/hunt-result-filter-component';
import { playbookBundleElementsToApply } from '../../../src/modules/playbook/playbook-types';
import { findPlaybookHuntRuns } from '../../../src/modules/hunt/hunt-playbook';
import { resumeSettledHuntPlaybooks } from '../../../src/modules/hunt/hunt-automation';
import { derivedHuntName } from '../../../src/modules/hunt/hunt-derivation';
import { huntHitKey } from '../../../src/modules/hunt/hunt-utils';

// A hunt connector deployed on a fresh platform: its user is in the Connectors group the platform creates at
// initialization, and it calls the API over HTTP with its own token, as the connectors SDK does
const CONNECTOR_ID = '0b6f2d1c-4e8a-4c3b-9d7e-5a1f2e3c4b06';
const SECURITY_PLATFORM_NAME = 'Hunt playbook test Splunk';
const CONNECTOR_EMAIL = 'hunt-playbook-connector@opencti.io';
const STEP_ID = 'hunt-step';

const REGISTER_CONNECTOR = gql`
  mutation RegisterConnector($input: RegisterConnectorInput) { registerConnector(input: $input) { id } }
`;
const HUNT_CONNECTOR_REGISTER = gql`
  mutation HuntConnectorRegister($input: HuntConnectorRegisterInput!) {
    huntConnectorRegister(input: $input) { id platform supports_indicators securityPlatform { id name } }
  }
`;
const HUNT_RUN_REPORT = gql`
  mutation HuntRunReport($id: ID!, $input: HuntRunReportInput!) { huntRunReport(id: $id, input: $input) { id hunt_run_status verdict hits_count } }
`;
const HUNT_ADD = gql`
  mutation HuntAdd($input: HuntAddInput!) { huntAdd(input: $input) { id } }
`;
const HUNT_DELETE = gql`
  mutation HuntDelete($id: ID!) { huntDelete(id: $id) }
`;

const huntRunsOf = (huntId: string) => topEntitiesList<BasicStoreEntityHuntRun>(testContext, ADMIN_USER, [ENTITY_TYPE_HUNT_RUN], {
  first: 100,
  filters: { mode: FilterMode.And, filters: [{ key: ['hunt_id'], values: [huntId] }], filterGroups: [] },
  noFiltersChecking: true,
});

const hit = (eventId: string) => ({
  event_id: eventId,
  timestamp: '2026-10-05T10:00:00Z',
  matched: [{ field: 'process.command_line', value_hash: 'd'.repeat(64), value_preview: 'powershell -enc DDDD' }],
  host: null,
});

describe('Hunt playbook components and hunt connectors of a fresh platform', () => {
  let token: string;
  let connectorUserId: string;
  let intrusionSet: { id: string; standard_id: string };
  let securityPlatformId: string;
  let huntId: string;
  const huntIds: string[] = [];

  // The connector reports a run as the connectors SDK does: over HTTP, with its token and the work of the dispatch
  const reportRun = async (runId: string, eventIds: string[]) => {
    const run = await internalLoadById<BasicStoreEntityHuntRun & { work_id?: string }>(testContext, ADMIN_USER, runId, { type: ENTITY_TYPE_HUNT_RUN });
    return queryInitPlatformAsTokenBearer(token, HUNT_RUN_REPORT, {
      id: runId,
      input: {
        work_id: run.work_id,
        status: 'completed',
        hits_count: eventIds.length,
        hits_sample: eventIds.map(hit),
        hit_keys: eventIds.map((eventId) => huntHitKey(hit(eventId))),
      },
    });
  };

  const notifyStep = (executionId: string, element: Record<string, unknown>, configuration: Record<string, unknown>) => {
    const notify = PLAYBOOK_HUNT_COMPONENT.notify as NonNullable<typeof PLAYBOOK_HUNT_COMPONENT.notify>;
    const bundle = { id: `bundle--${uuidv4()}`, type: 'bundle', spec_version: '2.1', objects: [element] };
    return notify({
      executionId,
      eventId: 'event-id',
      playbookId: uuidv4(),
      dataInstanceId: element.id,
      previousPlaybookNodeId: 'entry-step',
      playbookNode: {
        id: STEP_ID,
        name: 'Run hunts',
        component_id: PLAYBOOK_HUNT_COMPONENT.id,
        configuration: {
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
          hunt_ids: [],
          security_platform_ids: [],
          time_window_hours: 0,
          max_hunts: 10,
          wait_for_results: true,
          include_results: false,
          author_id: ADMIN_USER.id,
          ...configuration,
        },
      },
      bundle,
      previousStepBundle: bundle,
    } as unknown as Parameters<typeof notify>[0]);
  };

  const matchStep = async (executionId: string, instanceId: string, configuration: Record<string, unknown>) => {
    const executor = PLAYBOOK_HUNT_RESULT_FILTER.executor as NonNullable<typeof PLAYBOOK_HUNT_RESULT_FILTER.executor>;
    const result = await executor({
      executionId,
      dataInstanceId: instanceId,
      playbookId: uuidv4(),
      previousPlaybookNodeId: STEP_ID,
      playbookNode: { id: 'match-step', name: 'Match hunt results', component_id: PLAYBOOK_HUNT_RESULT_FILTER.id, configuration },
      bundle: { id: `bundle--${uuidv4()}`, type: 'bundle', spec_version: '2.1', objects: [] },
    } as unknown as Parameters<typeof executor>[0]);
    return result.output_port;
  };

  beforeAll(async () => {
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue(undefined);
    const created = await queryAsAdminWithSuccess({
      query: gql`mutation IntrusionSetAdd($input: IntrusionSetAddInput!) { intrusionSetAdd(input: $input) { id standard_id } }`,
      variables: { input: { name: 'Hunt playbook test intrusion set' } },
    });
    intrusionSet = created.data?.intrusionSetAdd;
    // The group and role the platform initialization creates for connectors, untouched
    const [connectorsGroup] = await fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_GROUP], {
      filters: { mode: FilterMode.And, filters: [{ key: ['name'], values: ['Connectors'] }], filterGroups: [] },
    });
    const user = await queryAsAdminWithSuccess({
      query: gql`mutation UserAdd($input: UserAddInput!) { userAdd(input: $input) { id } }`,
      variables: { input: { name: 'Hunt playbook test connector', user_email: CONNECTOR_EMAIL, password: 'HuntPlaybook1!', groups: [connectorsGroup.id], prevent_default_groups: true } },
    });
    connectorUserId = user.data?.userAdd.id;
    const tokenAdd = await queryAsAuthUser(await getAuthUser(connectorUserId), {
      query: gql`mutation UserTokenAdd($input: UserTokenAddInput!) { userTokenAdd(input: $input) { plaintext_token } }`,
      variables: { input: { name: 'Hunt connector', duration: 'DAYS_30' } },
    });
    token = tokenAdd.data?.userTokenAdd.plaintext_token;
    // The platform finds the user of a token in its cache, which takes the new token from a notification
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const me = await queryInitPlatformAsTokenBearer(token, gql`query { me { id } }`).catch(() => null);
      if (me && !me.errors && me.data?.me?.id === connectorUserId) {
        break;
      }
      await wait(250);
    }
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    for (let index = 0; index < huntIds.length; index += 1) {
      const runs = await huntRunsOf(huntIds[index]);
      for (let runIndex = 0; runIndex < runs.length; runIndex += 1) {
        await deleteElementById(testContext, ADMIN_USER, runs[runIndex].internal_id, ENTITY_TYPE_HUNT_RUN);
      }
      await queryAsAdmin({ query: HUNT_DELETE, variables: { id: huntIds[index] } });
    }
    await queryAsAdmin({ query: gql`mutation DeleteConnector($id: ID!) { deleteConnector(id: $id) }`, variables: { id: CONNECTOR_ID } });
    if (securityPlatformId) {
      await deleteElementById(testContext, ADMIN_USER, securityPlatformId, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
    }
    if (connectorUserId) {
      await deleteElementById(testContext, ADMIN_USER, connectorUserId, ENTITY_TYPE_USER);
    }
    await deleteElementById(testContext, ADMIN_USER, intrusionSet.id, ENTITY_TYPE_INTRUSION_SET);
  });

  it('should register a hunt connector of a fresh platform with its own token, and create its security platform', async () => {
    expect(token).toBeTruthy();
    const registered = await queryInitPlatformAsTokenBearer(token, REGISTER_CONNECTOR, {
      input: { id: CONNECTOR_ID, name: 'Hunt playbook test connector', type: 'INTERNAL_HUNT', scope: ['splunk'], auto: false, only_contextual: false },
    });
    expect(registered.errors).toBeUndefined();
    const huntRegistered = await queryInitPlatformAsTokenBearer(token, HUNT_CONNECTOR_REGISTER, {
      input: { connector_id: CONNECTOR_ID, platform: 'splunk', languages: ['spl'], security_platform_name: SECURITY_PLATFORM_NAME, supports_indicators: true },
    });
    expect(huntRegistered.errors).toBeUndefined();
    const connector = huntRegistered.data.huntConnectorRegister;
    expect(connector).toMatchObject({ platform: 'splunk', supports_indicators: true, securityPlatform: { name: SECURITY_PLATFORM_NAME } });
    securityPlatformId = connector.securityPlatform.id;
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    // The analysts read the security platform the connector created, and a hunt of every platform runs on it
    const platform = await queryAsAdminWithSuccess({ query: gql`query SecurityPlatform($id: String!) { securityPlatform(id: $id) { id name } }`, variables: { id: securityPlatformId } });
    expect(platform.data?.securityPlatform.name).toEqual(SECURITY_PLATFORM_NAME);
    const hunt = await queryAsAdminWithSuccess({
      query: HUNT_ADD,
      variables: {
        input: {
          name: 'Hunt playbook test hunt',
          huntTargets: [intrusionSet.id],
          native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr CommandLine="* -enc *"' }],
        },
      },
    });
    huntId = hunt.data?.huntAdd.id;
    huntIds.push(huntId);
    const started = await queryAsAdminWithSuccess({ query: gql`mutation HuntRunStart($id: ID!) { huntRunStart(id: $id) { id security_platform_id connector_id } }`, variables: { id: huntId } });
    const [run] = started.data?.huntRunStart ?? [];
    expect(run).toMatchObject({ security_platform_id: securityPlatformId, connector_id: CONNECTOR_ID });
    const reported = await reportRun(run.id, ['evt-fresh-1']);
    expect(reported.errors).toBeUndefined();
    expect(reported.data.huntRunReport).toMatchObject({ hunt_run_status: 'completed', hits_count: 1 });
  });

  it('should run the hunts targeting a threat of the bundle, wait for their results, and match them', async () => {
    const resume = vi.spyOn(playbookManager, 'playbookStepExecution').mockResolvedValue(true);
    const executionId = uuidv4();
    const element = { id: intrusionSet.standard_id, type: 'intrusion-set', spec_version: '2.1', name: 'Hunt playbook test intrusion set' };
    try {
      await notifyStep(executionId, element, { hunt_source: PLAYBOOK_HUNT_SOURCE_EXISTING });
      const runs = await findPlaybookHuntRuns(testContext, { executionId, instanceId: element.id, stepId: STEP_ID });
      expect(runs.map((run) => run.hunt_id)).toContain(huntId);
      expect(runs.every((run) => run.hunt_run_trigger === HUNT_RUN_TRIGGER_PLAYBOOK)).toBe(true);
      // The step waits: nothing continues before the runs are settled
      expect(runs.filter((run) => run.playbook_leader)).toHaveLength(1);
      await resumeSettledHuntPlaybooks(testContext);
      expect(resume).not.toHaveBeenCalled();
      for (let index = 0; index < runs.length; index += 1) {
        const reported = await reportRun(runs[index].internal_id, ['evt-playbook-1', 'evt-playbook-2']);
        expect(reported.errors).toBeUndefined();
      }
      await resumeSettledHuntPlaybooks(testContext);
      expect(resume).toHaveBeenCalledTimes(1);
      expect(resume.mock.calls[0][2]).toMatchObject({ execution_id: executionId, step_id: STEP_ID, data_instance_id: element.id });
      // Match hunt results routes on the outcome of the runs of the step
      const matching = { verdicts: ['true_positive', 'pending'], use_triage_proposals: true, min_hits: 2, require_incident: false };
      expect(await matchStep(executionId, element.id, matching)).toEqual('out');
      expect(await matchStep(executionId, element.id, { ...matching, min_hits: 1000 })).toEqual('no-match');
      expect(await matchStep(executionId, element.id, { ...matching, verdicts: ['benign'] })).toEqual('no-match');
      // Another entity of the execution has no run: it never matches
      expect(await matchStep(executionId, `intrusion-set--${uuidv4()}`, matching)).toEqual('no-match');
    } finally {
      resume.mockRestore();
    }
  });

  it('should derive a hunt from an indicator of the bundle, create it once, and run it', async () => {
    const resume = vi.spyOn(playbookManager, 'playbookStepExecution').mockResolvedValue(true);
    const created = await queryAsAdminWithSuccess({
      query: gql`mutation IndicatorAdd($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id standard_id } }`,
      variables: { input: { name: 'Hunt playbook test indicator', pattern: "[ipv4-addr:value = '203.0.113.77']", pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } },
    });
    const indicator = created.data?.indicatorAdd;
    const element = { id: indicator.standard_id, type: 'indicator', spec_version: '2.1', name: 'Hunt playbook test indicator', pattern: "[ipv4-addr:value = '203.0.113.77']", pattern_type: 'stix' };
    const derivedHunts = () => topEntitiesList<BasicStoreEntityHunt>(testContext, ADMIN_USER, [ENTITY_TYPE_HUNT], {
      filters: { mode: FilterMode.And, filters: [{ key: ['name'], values: [derivedHuntName('Hunt playbook test indicator')] }], filterGroups: [] },
    });
    try {
      const executionId = uuidv4();
      await notifyStep(executionId, element, { hunt_source: PLAYBOOK_HUNT_SOURCE_DERIVED, wait_for_results: false });
      const [derived] = await derivedHunts();
      expect(derived).toBeDefined();
      huntIds.push(derived.internal_id);
      expect(derived).toMatchObject({ hunt_type: 'indicators', hunt_status: 'active' });
      const runs = await findPlaybookHuntRuns(testContext, { executionId, instanceId: element.id, stepId: STEP_ID });
      expect(runs.map((run) => [run.hunt_id, run.connector_id])).toContainEqual([derived.internal_id, CONNECTOR_ID]);
      // Not waiting: the execution continues at once, through the output of the started runs
      expect(resume).toHaveBeenCalledTimes(1);
      // The next execution on the same indicator runs the same hunt again, without creating another one
      await notifyStep(uuidv4(), element, { hunt_source: PLAYBOOK_HUNT_SOURCE_DERIVED, wait_for_results: false });
      expect(await derivedHunts()).toHaveLength(1);
    } finally {
      resume.mockRestore();
      await deleteElementById(testContext, ADMIN_USER, indicator.id, ENTITY_TYPE_INDICATOR);
    }
  });
});
