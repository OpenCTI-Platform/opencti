import gql from 'graphql-tag';
import { Readable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, getAuthUser, testContext, USER_CONNECTOR, USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedError, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import * as enterpriseEdition from '../../../src/enterprise-edition/ee';
import * as huntStats from '../../../src/modules/hunt/hunt-stats';
import { createRelation, deleteElementById, patchAttribute } from '../../../src/database/middleware';
import { addSecurityCoverage, listSecurityCoverageResults, securityCoverageDelete } from '../../../src/modules/securityCoverage/securityCoverage-domain';
import { RELATION_HAS_COVERED } from '../../../src/schema/stixCoreRelationship';
import { addIntrusionSet } from '../../../src/domain/intrusionSet';
import { fullRelationsList, internalLoadById } from '../../../src/database/middleware-loader';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';
import type { BasicStoreEntity, BasicStoreRelation } from '../../../src/types/store';
import { addSecurityPlatform } from '../../../src/modules/securityPlatform/securityPlatform-domain';
import { ENTITY_TYPE_HUNT_RUN } from '../../../src/modules/hunt/huntRun/huntRun-types';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_OBSERVED_DATA, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';
import { addObservedData } from '../../../src/domain/observedData';
import { addStixSightingRelationship } from '../../../src/domain/stixSightingRelationship';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../src/modules/securityPlatform/securityPlatform-types';
import { getEntitiesListFromCache, resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_CONNECTOR } from '../../../src/schema/internalObject';
import type { BasicStoreEntityConnector } from '../../../src/types/connector';
import { importHuntPack, loadHuntPlanEntities, resolveHuntPlanPlatformIds } from '../../../src/modules/hunt/hunt-domain';
import { HUNT_INCIDENT_RECOMMENDATION } from '../../../src/modules/hunt/hunt-incident';
import { STIX_EXT_OCTI_HUNT } from '../../../src/types/stix-2-1-extensions';
import { HUNT_MANAGER_USER } from '../../../src/utils/access';
import { finalizeInterruptedHuntRuns } from '../../../src/modules/hunt/hunt-automation';
import { HUNT_RUN_RESULT_IDS_MAX } from '../../../src/modules/hunt/huntRun/huntRun-domain';
import { HUNT_CONFIG, huntHitKey } from '../../../src/modules/hunt/hunt-utils';

const CONNECTOR_ID = '0b7e4b54-1f4f-4bde-9e93-8d0f1d6a3c01';
const RESTRICTED_CONNECTOR_ID = '4c3f2a1d-8e7b-4d6c-9a5f-1b2c3d4e5f60';
const SECURITY_PLATFORM_NAME = 'Hunt test Splunk';
const TECHNIQUE_MITRE_ID = 'T1999.001';
const SIGMA_RULE = `title: Hunt test encoded command
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: ' -enc '
  condition: selection
tags:
  - attack.t1999.001
`;

const HUNT_FIELDS = `
  id
  standard_id
  name
  hunt_type
  hunt_status
  hunt_source_kind
  hunt_schedule
  escalation_threshold
  next_run_at
  sigmaValidation { valid errors title detection_fields attack_techniques }
  huntTechniques { id x_mitre_id }
  huntTargets { id }
  native_queries { platform language query }
`;
const RUN_FIELDS = `
  id
  hunt_id
  hunt_run_status
  hunt_run_trigger
  hunt_run_mode
  connector_id
  security_platform_id
  work_id
  hits_count
  results_truncated
  translated_query
  verdict
  verdict_source
  incident_id
  draft_id
  result_ids
  evidence_sample { kind label quote field value_hash value_preview count matched }
  hits_sample { event_id timestamp detection host user process matched { field value_hash value_preview value_complete } }
  first_hit_at
  last_hit_at
  evidence_sources
  attempt
  next_retry_at
  error_message
  last_evidence_at
`;

const REGISTER_CONNECTOR = gql`
  mutation RegisterConnector($input: RegisterConnectorInput) {
    registerConnector(input: $input) { id connector_type }
  }
`;
const HUNT_CONNECTOR_REGISTER = gql`
  mutation HuntConnectorRegister($input: HuntConnectorRegisterInput!) {
    huntConnectorRegister(input: $input) { id platform languages active supports_preview securityPlatform { id name } }
  }
`;
const HUNT_CONNECTORS = gql`
  query HuntConnectors { huntConnectors(onlyAlive: false) { id platform languages } }
`;
const LIVE_HUNT_CONNECTORS = gql`
  query LiveHuntConnectors { huntConnectors(onlyAlive: true) { id active } }
`;
const PING_CONNECTOR = gql`
  mutation PingConnector($id: ID!, $state: String) { pingConnector(id: $id, state: $state) { id active } }
`;
const CONNECTORS_HUNT = gql`
  query ConnectorsHunt { connectors { id connector_type hunt { platform languages supports_preview securityPlatform { name } } } }
`;
const SIGMA_VALIDATE = gql`
  query HuntSigmaValidate($sigma_rule: String!) { huntSigmaValidate(sigma_rule: $sigma_rule) { valid errors title } }
`;
const HUNT_ADD = gql`
  mutation HuntAdd($input: HuntAddInput!) { huntAdd(input: $input) { ${HUNT_FIELDS} } }
`;
const HUNT_READ = gql`
  query Hunt($id: String!) { hunt(id: $id) { ${HUNT_FIELDS} last_run_status last_hits_count } }
`;
const HUNTS_LIST = gql`
  query Hunts($filters: FilterGroup) { hunts(filters: $filters) { edges { node { ${HUNT_FIELDS} } } } }
`;
const HUNT_FIELD_PATCH = gql`
  mutation HuntFieldPatch($id: ID!, $input: [EditInput]!) { huntFieldPatch(id: $id, input: $input) { id hunt_status hunt_schedule next_run_at } }
`;
const HUNT_RUN_START = gql`
  mutation HuntRunStart($id: ID!, $input: HuntRunStartInput) { huntRunStart(id: $id, input: $input) { ${RUN_FIELDS} } }
`;
const HUNT_TEST_QUERY = gql`
  mutation HuntTestQuery($id: ID!, $securityPlatformId: ID) { huntTestQuery(id: $id, securityPlatformId: $securityPlatformId) { ${RUN_FIELDS} } }
`;
const HUNT_RUN_READ = gql`
  query HuntRunRead($id: String!) { huntRun(id: $id) { id } }
`;
const HUNT_RUN_REPORT = gql`
  mutation HuntRunReport($id: ID!, $input: HuntRunReportInput!) { huntRunReport(id: $id, input: $input) { ${RUN_FIELDS} } }
`;

// A hunt connector reports a run with the work it was dispatched with
const reportAsConnector = async (request: { query: typeof HUNT_RUN_REPORT; variables: { id: string; input: Record<string, unknown> } }) => {
  const run = await internalLoadById<BasicStoreEntity & { work_id?: string }>(testContext, ADMIN_USER, request.variables.id, { type: ENTITY_TYPE_HUNT_RUN });
  return queryAsUserWithSuccess(USER_CONNECTOR, { ...request, variables: { ...request.variables, input: { work_id: run?.work_id, ...request.variables.input } } });
};
const HUNT_RUN_STATE = gql`
  query HuntRunState($id: String!) { huntRun(id: $id) { ${RUN_FIELDS} } }
`;
const HUNT_RUN_KNOWN_HITS = gql`
  query HuntRunKnownHits($id: String!) {
    huntRun(id: $id) {
      id hits_count hits_new_count hits_recurring_count hits_identified incident_continued sightings_created_count incident_id draft_id
      hits_sample { event_id is_new times_seen known_since }
    }
  }
`;
const HUNT_KNOWN_HITS = gql`
  query HuntKnownHits($id: String!) { hunt(id: $id) { id last_hits_count last_new_hits_count knownHits { distinct_count first_new_at last_new_at } } }
`;
const HUNT_RUN_VERDICT = gql`
  mutation HuntRunSetVerdict($id: ID!, $input: HuntRunVerdictInput!) { huntRunSetVerdict(id: $id, input: $input) { ${RUN_FIELDS} } }
`;
const HUNT_RUN_EVIDENCE = gql`
  mutation HuntRunEvidenceAdd($id: ID!, $input: HuntRunEvidenceAddInput!) { huntRunEvidenceAdd(id: $id, input: $input) { ${RUN_FIELDS} } }
`;
const OBSERVED_DATA_ADD = gql`
  mutation ObservedDataAdd($input: ObservedDataAddInput!) { observedDataAdd(input: $input) { id } }
`;
const OBSERVED_DATA_FIELD_PATCH = gql`
  mutation ObservedDataFieldPatch($id: ID!, $input: [EditInput]!) { observedDataEdit(id: $id) { fieldPatch(input: $input) { id } } }
`;
const SIGHTING_ADD = gql`
  mutation SightingAdd($input: StixSightingRelationshipAddInput!) { stixSightingRelationshipAdd(input: $input) { id } }
`;
const SIGHTING_FIELD_PATCH = gql`
  mutation SightingFieldPatch($id: ID!, $input: [EditInput]!) { stixSightingRelationshipEdit(id: $id) { fieldPatch(input: $input) { id } } }
`;
const HUNT_RUNS = gql`
  query HuntRuns($filters: FilterGroup) { huntRuns(filters: $filters, first: 50) { edges { node { id hunt_run_mode verdict } } pageInfo { globalCount } } }
`;
const HUNT_STATISTICS = gql`
  query HuntStatistics($huntId: ID) {
    huntStatistics(huntId: $huntId) { runs_count completed_runs_count hits_total benign_count true_positive_count runs_per_platform { label value } }
  }
`;
const HUNT_PACK_EXPORT = gql`
  query HuntPackExport($ids: [ID!]!) { huntPackExport(ids: $ids) }
`;
const HUNT_VALIDATE_EMULATION = gql`
  mutation HuntValidateFromEmulation($input: HuntValidateFromEmulationInput!) {
    huntValidateFromEmulation(input: $input) { hunts_count runs { id hunt_run_trigger aev_inject_id technique_id } }
  }
`;
const HUNT_DELETE = gql`
  mutation HuntDelete($id: ID!) { huntDelete(id: $id) }
`;
const DRAFT_DELETE = gql`
  mutation DraftWorkspaceDelete($id: ID!) { draftWorkspaceDelete(id: $id) }
`;

const runFilters = (huntId: string) => ({ mode: 'and', filters: [{ key: ['hunt_id'], values: [huntId] }], filterGroups: [] });

describe('Hunt resolvers', () => {
  let techniqueId: string;
  let intrusionSetId: string;
  let intrusionSetStandardId: string;
  let securityPlatformId: string;
  let huntId: string;
  let firstRunId: string;
  let secondRunId: string;
  let emulationRunId: string;
  const draftIds: string[] = [];
  const huntIds: string[] = [];

  beforeAll(async () => {
    const technique = await queryAsAdminWithSuccess({
      query: gql`mutation AttackPatternAdd($input: AttackPatternAddInput!) { attackPatternAdd(input: $input) { id } }`,
      variables: { input: { name: 'Hunt test technique', x_mitre_id: TECHNIQUE_MITRE_ID } },
    });
    techniqueId = technique.data?.attackPatternAdd.id;
    const intrusionSet = await queryAsAdminWithSuccess({
      query: gql`mutation IntrusionSetAdd($input: IntrusionSetAddInput!) { intrusionSetAdd(input: $input) { id standard_id } }`,
      variables: { input: { name: 'Hunt test intrusion set' } },
    });
    intrusionSetId = intrusionSet.data?.intrusionSetAdd.id;
    intrusionSetStandardId = intrusionSet.data?.intrusionSetAdd.standard_id;
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REGISTER_CONNECTOR,
      variables: { input: { id: CONNECTOR_ID, name: 'Hunt test connector', type: 'INTERNAL_HUNT', scope: ['splunk'], auto: false, only_contextual: false } },
    });
  });

  afterAll(async () => {
    for (let index = 0; index < huntIds.length; index += 1) {
      await queryAsAdmin({ query: HUNT_DELETE, variables: { id: huntIds[index] } });
    }
    for (let index = 0; index < draftIds.length; index += 1) {
      await queryAsAdmin({ query: DRAFT_DELETE, variables: { id: draftIds[index] } });
    }
    await queryAsAdmin({ query: gql`mutation DeleteConnector($id: ID!) { deleteConnector(id: $id) }`, variables: { id: CONNECTOR_ID } });
    if (securityPlatformId) {
      await deleteElementById(testContext, ADMIN_USER, securityPlatformId, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
    }
    await deleteElementById(testContext, ADMIN_USER, techniqueId, ENTITY_TYPE_ATTACK_PATTERN);
    await deleteElementById(testContext, ADMIN_USER, intrusionSetId, ENTITY_TYPE_INTRUSION_SET);
    vi.restoreAllMocks();
  });

  it('should register a hunt connector and its security platform', async () => {
    const registration = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: HUNT_CONNECTOR_REGISTER,
      variables: { input: { connector_id: CONNECTOR_ID, platform: 'Splunk', languages: ['SPL', 'spl'], security_platform_name: SECURITY_PLATFORM_NAME } },
    });
    const connector = registration.data?.huntConnectorRegister;
    expect(connector.platform).toEqual('splunk');
    expect(connector.languages).toEqual(['spl']);
    expect(connector.supports_preview).toBe(true);
    expect(connector.securityPlatform.name).toEqual(SECURITY_PLATFORM_NAME);
    securityPlatformId = connector.securityPlatform.id;
    const list = await queryAsAdminWithSuccess({ query: HUNT_CONNECTORS });
    expect(list.data?.huntConnectors.map((c: { id: string }) => c.id)).toContain(CONNECTOR_ID);
    // The connector page reads the hunted platform from the connector itself, null for every other type
    const connectors = await queryAsAdminWithSuccess({ query: CONNECTORS_HUNT });
    type ConnectorHunt = { platform: string; languages: string[]; supports_preview: boolean; securityPlatform: { name: string } };
    const all = connectors.data?.connectors as { id: string; connector_type: string; hunt: ConnectorHunt | null }[];
    const huntConnector = all.find((c) => c.id === CONNECTOR_ID);
    expect(huntConnector?.hunt).toEqual({ platform: 'splunk', languages: ['spl'], supports_preview: true, securityPlatform: { name: SECURITY_PLATFORM_NAME } });
    expect(all.filter((c) => c.connector_type !== 'INTERNAL_HUNT').every((c) => c.hunt === null)).toBe(true);
  });

  it('should keep a pinging hunt connector live while its cached copy is stale', async () => {
    // The entity cache loads the connector as it was 10 minutes ago, and a ping never refreshes the cache
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    await patchAttribute(testContext, ADMIN_USER, CONNECTOR_ID, ENTITY_TYPE_CONNECTOR, { updated_at: tenMinutesAgo });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    const cached = await getEntitiesListFromCache<BasicStoreEntityConnector>(testContext, ADMIN_USER, ENTITY_TYPE_CONNECTOR);
    expect(cached.find((c) => c.internal_id === CONNECTOR_ID)?.active).toBe(false);
    const offline = await queryAsAdminWithSuccess({ query: LIVE_HUNT_CONNECTORS });
    expect(offline.data?.huntConnectors.map((c: { id: string }) => c.id)).not.toContain(CONNECTOR_ID);
    await queryAsUserWithSuccess(USER_CONNECTOR, { query: PING_CONNECTOR, variables: { id: CONNECTOR_ID, state: '{}' } });
    const live = await queryAsAdminWithSuccess({ query: LIVE_HUNT_CONNECTORS });
    expect(live.data?.huntConnectors.find((c: { id: string }) => c.id === CONNECTOR_ID)).toEqual({ id: CONNECTOR_ID, active: true });
  });

  it('should refuse an unknown platform and a telemetry connector without security platform', async () => {
    const unknown = await queryAsAdmin({ query: HUNT_CONNECTOR_REGISTER, variables: { input: { connector_id: CONNECTOR_ID, platform: 'nowhere', languages: ['x'] } } });
    expect(unknown.errors?.[0].message).toContain('Hunt platform must be one of');
    const noPlatform = await queryAsAdmin({ query: HUNT_CONNECTOR_REGISTER, variables: { input: { connector_id: CONNECTOR_ID, platform: 'splunk', languages: ['spl'] } } });
    expect(noPlatform.errors?.[0].message).toContain('must declare the security platform');
  });

  it('should validate Sigma rules', async () => {
    const valid = await queryAsAdminWithSuccess({ query: SIGMA_VALIDATE, variables: { sigma_rule: SIGMA_RULE } });
    expect(valid.data?.huntSigmaValidate).toEqual({ valid: true, errors: [], title: 'Hunt test encoded command' });
    const invalid = await queryAsAdminWithSuccess({ query: SIGMA_VALIDATE, variables: { sigma_rule: 'title: broken' } });
    expect(invalid.data?.huntSigmaValidate.valid).toBe(false);
  });

  it('should plan a hunt from the threats, techniques and indicators a report contains', async () => {
    const { threats, techniques, indicators } = await loadHuntPlanEntities(testContext, ADMIN_USER, ['report--f3e554eb-60f5-587c-9191-4f25e9ba9f32']);
    expect(threats.map((threat) => threat.entity_type)).toEqual(expect.arrayContaining([ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE]));
    expect(techniques.length).toBeGreaterThan(0);
    expect(techniques.every((technique) => technique.entity_type === ENTITY_TYPE_ATTACK_PATTERN)).toBe(true);
    expect(indicators.length).toBeGreaterThan(0);
  });

  it('should create a manual hunt linked to the techniques of its Sigma rule', async () => {
    const hunt = await queryAsAdminWithSuccess({
      query: HUNT_ADD,
      variables: {
        input: {
          name: 'Hunt test manual hunt',
          hypothesis: 'If the intrusion set is active, encoded commands run on endpoints',
          sigma_rule: SIGMA_RULE,
          huntTargets: [intrusionSetId],
          escalation_threshold: 2,
          // Its runs are started by hand: they open an incident draft above the threshold only on opt-in
          escalate_manual_runs: true,
          native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr CommandLine="* -enc *"' }],
        },
      },
    });
    const created = hunt.data?.huntAdd;
    huntId = created.id;
    huntIds.push(huntId);
    expect(created.hunt_type).toEqual('telemetry');
    expect(created.hunt_status).toEqual('active');
    expect(created.hunt_source_kind).toEqual('analyst');
    expect(created.hunt_schedule).toEqual('manual');
    expect(created.next_run_at).toBeNull();
    expect(created.sigmaValidation.valid).toBe(true);
    expect(created.huntTechniques.map((t: { x_mitre_id: string }) => t.x_mitre_id)).toEqual([TECHNIQUE_MITRE_ID]);
    expect(created.huntTargets.map((t: { id: string }) => t.id)).toEqual([intrusionSetId]);
  });

  it('should list hunts with their techniques and targets, as the hunt query returns them', async () => {
    const listed = await queryAsAdminWithSuccess({
      query: HUNTS_LIST,
      variables: { filters: { mode: 'and', filters: [{ key: ['id'], values: [huntId], operator: 'eq', mode: 'or' }], filterGroups: [] } },
    });
    const nodes = listed.data?.hunts.edges.map((edge: { node: { id: string } }) => edge.node);
    expect(nodes.map((node: { id: string }) => node.id)).toEqual([huntId]);
    expect(nodes[0].huntTechniques.map((t: { x_mitre_id: string }) => t.x_mitre_id)).toEqual([TECHNIQUE_MITRE_ID]);
    expect(nodes[0].huntTargets.map((t: { id: string }) => t.id)).toEqual([intrusionSetId]);
    const read = await queryAsAdminWithSuccess({ query: HUNT_READ, variables: { id: huntId } });
    expect(nodes[0].huntTechniques).toEqual(read.data?.hunt.huntTechniques);
    expect(nodes[0].huntTargets).toEqual(read.data?.hunt.huntTargets);
  });

  it('should refuse an invalid Sigma rule and a schedule firing too often', async () => {
    const invalid = await queryAsAdmin({ query: HUNT_ADD, variables: { input: { name: 'Hunt test invalid', sigma_rule: 'title: broken' } } });
    expect(invalid.errors?.length).toBeGreaterThan(0);
    const tooOften = await queryAsAdmin({ query: HUNT_ADD, variables: { input: { name: 'Hunt test too often', sigma_rule: SIGMA_RULE, hunt_schedule: '* * * * *' } } });
    expect(tooOften.errors?.length).toBeGreaterThan(0);
  });

  it('should gate autonomous schedules with Enterprise Edition', async () => {
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockRejectedValueOnce(new Error('Enterprise edition is not enabled'));
    const refused = await queryAsAdmin({ query: HUNT_FIELD_PATCH, variables: { id: huntId, input: [{ key: 'hunt_schedule', value: ['0 */6 * * *'] }] } });
    expect(refused.errors?.length).toBeGreaterThan(0);
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue(undefined);
    const scheduled = await queryAsAdminWithSuccess({ query: HUNT_FIELD_PATCH, variables: { id: huntId, input: [{ key: 'hunt_schedule', value: ['0 */6 * * *'] }] } });
    expect(scheduled.data?.huntFieldPatch.hunt_schedule).toEqual('0 */6 * * *');
    const read = await queryAsAdminWithSuccess({ query: HUNT_READ, variables: { id: huntId } });
    expect(read.data?.hunt.next_run_at).not.toBeNull();
    await queryAsAdminWithSuccess({ query: HUNT_FIELD_PATCH, variables: { id: huntId, input: [{ key: 'hunt_schedule', value: ['manual'] }] } });
  });

  it('should start a run on the hunt connector of the security platform', async () => {
    const runs = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: huntId, input: { time_window_hours: 48 } } });
    expect(runs.data?.huntRunStart).toHaveLength(1);
    const [run] = runs.data?.huntRunStart ?? [];
    firstRunId = run.id;
    expect(run.hunt_run_status).toEqual('queued');
    expect(run.hunt_run_trigger).toEqual('manual');
    expect(run.connector_id).toEqual(CONNECTOR_ID);
    expect(run.security_platform_id).toEqual(securityPlatformId);
    expect(run.verdict).toEqual('pending');
  });

  it('should only accept reports from the hunt connector', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: HUNT_RUN_REPORT, variables: { id: firstRunId, input: { status: 'running' } } });
    // Hunt connectors can share a user: without the work of the dispatch, or with another one, the report is refused
    const dispatched = await internalLoadById<BasicStoreEntity & { work_id?: string }>(testContext, ADMIN_USER, firstRunId, { type: ENTITY_TYPE_HUNT_RUN });
    expect(dispatched.work_id).toBeTruthy();
    await queryAsUserIsExpectedForbidden(USER_CONNECTOR, { query: HUNT_RUN_REPORT, variables: { id: firstRunId, input: { status: 'running' } } });
    await queryAsUserIsExpectedForbidden(USER_CONNECTOR, { query: HUNT_RUN_REPORT, variables: { id: firstRunId, input: { status: 'running', work_id: 'another-work' } } });
    // A run without work was never handed to a connector (still queued, or mid-dispatch): no connector can report it
    await patchAttribute(testContext, ADMIN_USER, firstRunId, ENTITY_TYPE_HUNT_RUN, { work_id: null });
    try {
      await queryAsUserIsExpectedForbidden(USER_CONNECTOR, { query: HUNT_RUN_REPORT, variables: { id: firstRunId, input: { status: 'running' } } });
      await queryAsUserIsExpectedForbidden(USER_CONNECTOR, { query: HUNT_RUN_REPORT, variables: { id: firstRunId, input: { status: 'running', work_id: dispatched.work_id } } });
    } finally {
      await patchAttribute(testContext, ADMIN_USER, firstRunId, ENTITY_TYPE_HUNT_RUN, { work_id: dispatched.work_id });
    }
    const queued = await queryAsAdmin({ query: HUNT_RUN_REPORT, variables: { id: firstRunId, input: { status: 'queued' } } });
    expect(queued.errors?.[0].message).toContain('can only report a running, completed, failed or timeout status');
  });

  it('should only let the hunt connector of a run attribute observed data and sightings to it', async () => {
    const dispatched = await internalLoadById<BasicStoreEntity & { work_id?: string }>(testContext, ADMIN_USER, firstRunId, { type: ENTITY_TYPE_HUNT_RUN });
    const observedDataInput = {
      first_observed: '2026-10-01T00:00:00.000Z',
      last_observed: '2026-10-01T01:00:00.000Z',
      number_observed: 1,
      objects: [intrusionSetId],
      x_opencti_hunt_run_id: firstRunId,
    };
    const sightingInput = { fromId: intrusionSetId, toId: securityPlatformId, attribute_count: 1, x_opencti_hunt_run_id: firstRunId };
    // A knowledge editor, and the connector outside the work of the dispatch, cannot make evidence of the run
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: OBSERVED_DATA_ADD, variables: { input: observedDataInput } });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: SIGHTING_ADD, variables: { input: sightingInput } });
    await queryAsUserIsExpectedForbidden(USER_CONNECTOR, { query: SIGHTING_ADD, variables: { input: sightingInput } });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: SIGHTING_ADD, variables: { input: { ...sightingInput, x_opencti_hunt_run_id: 'unknown-run' } } });
    // The hunt connector of the run, in the work of the dispatch, as the worker ingests its bundle
    const connectorUser = await getAuthUser(USER_CONNECTOR.id);
    const workContext = { ...testContext, workId: dispatched.work_id };
    const observedData = await addObservedData(workContext, connectorUser, observedDataInput);
    const sighting = await addStixSightingRelationship(workContext, connectorUser, sightingInput);
    try {
      expect(observedData.x_opencti_hunt_run_id).toEqual(firstRunId);
      expect(sighting.x_opencti_hunt_run_id).toEqual(firstRunId);
      // An editor can neither clear the attribution nor move it to another run
      await queryAsUserIsExpectedForbidden(USER_EDITOR, {
        query: SIGHTING_FIELD_PATCH,
        variables: { id: sighting.id, input: [{ key: 'x_opencti_hunt_run_id', value: [''] }] },
      });
      await queryAsUserIsExpectedForbidden(USER_EDITOR, {
        query: OBSERVED_DATA_FIELD_PATCH,
        variables: { id: observedData.id, input: [{ key: 'x_opencti_hunt_run_id', value: ['another-run'] }] },
      });
      const kept = await internalLoadById<BasicStoreEntity & { x_opencti_hunt_run_id?: string }>(testContext, ADMIN_USER, sighting.id, { type: STIX_SIGHTING_RELATIONSHIP });
      expect(kept.x_opencti_hunt_run_id).toEqual(firstRunId);
    } finally {
      await deleteElementById(testContext, ADMIN_USER, sighting.id, STIX_SIGHTING_RELATIONSHIP);
      await deleteElementById(testContext, ADMIN_USER, observedData.id, ENTITY_TYPE_CONTAINER_OBSERVED_DATA);
    }
  });

  it('should complete a run without hits as benign', async () => {
    await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: firstRunId, input: { status: 'running', translated_query: 'index=edr', query_language: 'spl' } } });
    const completed = await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: firstRunId, input: { status: 'completed', hits_count: 0, truncated: false, cost_ms: 120 } } });
    const run = completed.data?.huntRunReport;
    expect(run.hunt_run_status).toEqual('completed');
    expect(run.verdict).toEqual('benign');
    expect(run.verdict_source).toEqual('auto');
    const again = await queryAsAdmin({ query: HUNT_RUN_REPORT, variables: { id: firstRunId, input: { status: 'completed' } } });
    expect(again.errors?.[0].message).toContain('already terminated');
    const hunt = await queryAsAdminWithSuccess({ query: HUNT_READ, variables: { id: huntId } });
    expect(hunt.data?.hunt.last_run_status).toEqual('completed');
    expect(hunt.data?.hunt.last_hits_count).toEqual(0);
  });

  it('should complete a finalization interrupted after the terminal report', async () => {
    const interrupt = (extra: Record<string, unknown> = {}) => patchAttribute(testContext, HUNT_MANAGER_USER, firstRunId, ENTITY_TYPE_HUNT_RUN, { verdict: 'pending', verdict_source: null, ...extra });
    const readRun = async () => (await queryAsAdminWithSuccess({ query: HUNT_RUN_STATE, variables: { id: firstRunId } })).data?.huntRun;
    // The hunt manager completes it once the finalization is overdue
    await interrupt({ completed_at: new Date(Date.now() - 10 * 60000).toISOString() });
    expect(await finalizeInterruptedHuntRuns(testContext)).toBeGreaterThanOrEqual(1);
    expect(await readRun()).toMatchObject({ hunt_run_status: 'completed', verdict: 'benign', verdict_source: 'auto' });
    // A report of the connector on the interrupted run completes it instead of being refused, then the run is closed
    await interrupt();
    const recovered = await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: firstRunId, input: { status: 'failed', error: 'late' } } });
    expect(recovered.data?.huntRunReport).toMatchObject({ hunt_run_status: 'completed', verdict: 'benign', verdict_source: 'auto' });
    const again = await queryAsAdmin({ query: HUNT_RUN_REPORT, variables: { id: firstRunId, input: { status: 'completed' } } });
    expect(again.errors?.[0].message).toContain('already terminated');
  });

  it('should open an Incident draft above the escalation threshold and store hashed evidence only', async () => {
    const runs = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: huntId } });
    secondRunId = runs.data?.huntRunStart[0].id;
    const completed = await reportAsConnector({
      query: HUNT_RUN_REPORT,
      variables: {
        id: secondRunId,
        input: {
          status: 'completed',
          hits_count: 5,
          distinct_entities: 2,
          result_ids: [intrusionSetStandardId, 'not a STIX id', 'indicator--not-a-uuid'],
          evidence_sample: [
            { field: 'metadata.log_type', value_hash: 'WINEVTLOG', value_preview: 'WINEVTLOG', count: 9 },
            { field: 'process.command_line', value_hash: 'powershell -enc AAAA', value_preview: 'powershell -enc AAAA', count: 5 },
          ],
          // The per-hit evidence of the connectors SDK, its preview truncated
          hits_sample: [{
            event_id: 'evt-1',
            timestamp: '2026-10-05T10:00:00Z',
            detection: null,
            matched: [{ field: 'process.command_line', value_hash: 'a'.repeat(64), value_preview: 'powershell -enc AAAA' }],
            host: null,
            user: null,
            process: 'powershell.exe',
          }],
        },
      },
    });
    const run = completed.data?.huntRunReport;
    expect(run.hits_sample).toEqual([{
      event_id: 'evt-1',
      timestamp: expect.anything(),
      detection: null,
      host: null,
      user: null,
      process: 'powershell.exe',
      matched: [{ field: 'process.command_line', value_hash: expect.stringMatching(/^[a-f0-9]{64}$/), value_preview: 'powershell -enc AAAA', value_complete: false }],
    }]);
    expect(run.hits_sample[0].matched[0].value_hash).not.toEqual('a'.repeat(64));
    expect(new Date(run.hits_sample[0].timestamp).toISOString()).toEqual('2026-10-05T10:00:00.000Z');
    expect(new Date(run.first_hit_at).toISOString()).toEqual('2026-10-05T10:00:00.000Z');
    // Only STIX identifiers are recorded from a connector report, then the sighting the platform keeps for the hunt
    const stored = await internalLoadById<BasicStoreEntity & { result_ids?: string[] }>(testContext, ADMIN_USER, secondRunId, { type: ENTITY_TYPE_HUNT_RUN });
    expect(stored.result_ids?.[0]).toEqual(intrusionSetStandardId);
    expect(stored.result_ids?.slice(1)).toEqual([expect.stringMatching(/^sighting--/)]);
    expect(run.verdict).toEqual('pending');
    expect(run.incident_id).toBeTruthy();
    expect(run.draft_id).toBeTruthy();
    draftIds.push(run.draft_id);
    // A raw value sent as a hash is hashed again by the platform
    expect(run.evidence_sample[0].value_hash).toMatch(/^[a-f0-9]{64}$/);
    // The field a hit matched comes before metadata seen more often
    expect(run.evidence_sample[0]).toMatchObject({ kind: 'tool_result', label: 'process.command_line', quote: 'powershell -enc AAAA', count: 5, matched: true });
    // Draft-first: the incident only exists in its draft workspace
    const live = await queryAsAdmin({ query: gql`query Incident($id: String!) { incident(id: $id) { id } }`, variables: { id: run.incident_id } });
    expect(live.data?.incident).toBeNull();
    const inDraft = await queryAsAdmin({ query: gql`query Incident($id: String!) { incident(id: $id) { id description } }`, variables: { id: run.incident_id } }, run.draft_id);
    expect(inDraft.data?.incident.description).toContain(HUNT_INCIDENT_RECOMMENDATION);
    expect(inDraft.data?.incident.description).toContain('- 2026-10-05T10:00:00.000Z, process powershell.exe, process.command_line = powershell -enc AAAA');
    // Draft workspaces are listed to every user with draft access: the workspace carries no detail of the hunt
    const workspace = await queryAsAdminWithSuccess({ query: gql`query HuntDraft($id: String!) { draftWorkspace(id: $id) { name description } }`, variables: { id: run.draft_id } });
    expect(workspace.data?.draftWorkspace.name).toEqual(`Hunt incident - run ${secondRunId}`);
    const huntName = (await queryAsAdminWithSuccess({ query: HUNT_READ, variables: { id: huntId } })).data?.hunt.name;
    expect(huntName).toBeTruthy();
    expect(`${workspace.data?.draftWorkspace.name} ${workspace.data?.draftWorkspace.description}`).not.toContain(huntName);
  });

  it('should record the verdict of an analyst without opening a second incident', async () => {
    // Pending is the state of a run waiting for its verdict, never a verdict that would end its finalization
    const pending = await queryAsAdmin({ query: HUNT_RUN_VERDICT, variables: { id: secondRunId, input: { verdict: 'pending' } } });
    expect(pending.errors?.[0].message).toContain('A verdict is true positive, benign or inconclusive');
    const verdict = await queryAsAdminWithSuccess({
      query: HUNT_RUN_VERDICT,
      variables: { id: secondRunId, input: { verdict: 'true_positive', hunt_analyst_feedback: 'Confirmed on two hosts' } },
    });
    const run = verdict.data?.huntRunSetVerdict;
    expect(run.verdict).toEqual('true_positive');
    expect(run.verdict_source).toEqual('analyst');
    const preview = await queryAsAdminWithSuccess({ query: HUNT_TEST_QUERY, variables: { id: huntId, securityPlatformId } });
    const auto = await queryAsAdmin({ query: HUNT_RUN_VERDICT, variables: { id: preview.data?.huntTestQuery.id, input: { verdict: 'benign' } } });
    expect(auto.errors?.[0].message).toContain('A translation preview has no verdict');
    // The connector answers the preview, which then stops occupying one of its concurrent run slots
    await reportAsConnector({
      query: HUNT_RUN_REPORT,
      variables: { id: preview.data?.huntTestQuery.id, input: { status: 'completed', translated_query: 'index=edr', query_language: 'spl' } },
    });
  });

  it('should keep the verdict of an analyst when late evidence reaches the run', async () => {
    const evidence = await queryAsAdminWithSuccess({
      query: HUNT_RUN_EVIDENCE,
      variables: { id: secondRunId, input: { result_ids: [intrusionSetId], hits_count: 1, source: 'splunk-alert-action' } },
    });
    expect(evidence.data?.huntRunEvidenceAdd).toMatchObject({ hits_count: 6, verdict: 'true_positive', verdict_source: 'analyst' });
    const hunt = await queryAsAdminWithSuccess({ query: HUNT_READ, variables: { id: huntId } });
    expect(hunt.data?.hunt.last_hits_count).toEqual(6);
  });

  it('should finalize again a run with an automatic verdict when late evidence brings hits', async () => {
    const evidence = await queryAsAdminWithSuccess({
      query: HUNT_RUN_EVIDENCE,
      variables: { id: firstRunId, input: { result_ids: [intrusionSetId], hits_count: 3, source: 'splunk-alert-action', security_platform_id: securityPlatformId } },
    });
    const run = evidence.data?.huntRunEvidenceAdd;
    expect(run.hits_count).toEqual(3);
    // The benign verdict of the run without hits is computed again: hits above the escalation threshold wait for triage
    // with an Incident draft
    expect(run.verdict).toEqual('pending');
    expect(run.verdict_source).toEqual('auto');
    expect(run.incident_id).toBeTruthy();
    expect(run.draft_id).toBeTruthy();
    draftIds.push(run.draft_id);
    // The sighting of the technique the hunt keeps on the platform, updated by this run too
    expect(run.result_ids[0]).toEqual(intrusionSetStandardId);
    expect(run.result_ids.slice(1)).toEqual([expect.stringMatching(/^sighting--/)]);
    expect(run.evidence_sources).toEqual(['splunk-alert-action']);
    const older = await queryAsAdminWithSuccess({
      query: HUNT_RUN_EVIDENCE,
      variables: { id: firstRunId, input: { result_ids: [intrusionSetId], observed_at: '2020-01-01T00:00:00.000Z' } },
    });
    expect(older.data?.huntRunEvidenceAdd.last_evidence_at).toEqual(run.last_evidence_at);
    const unknown = await queryAsAdmin({ query: HUNT_RUN_EVIDENCE, variables: { id: firstRunId, input: { result_ids: ['sighting--00000000-0000-4000-8000-000000000000'] } } });
    expect(unknown.errors?.[0].message).toContain('cannot be found or are not accessible');
  });

  it('should count a hit once across runs: a second run over the same events has no new hit, no new sighting, no new incident', async () => {
    const created = await queryAsAdminWithSuccess({
      query: HUNT_ADD,
      variables: {
        input: {
          name: 'Hunt test known hits',
          hypothesis: 'Encoded commands keep running on the same endpoints',
          sigma_rule: SIGMA_RULE,
          escalation_threshold: 2,
          escalate_manual_runs: true,
          native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr CommandLine="* -enc *"' }],
        },
      },
    });
    const knownHuntId = created.data?.huntAdd.id;
    try {
      const events = ['evt-a', 'evt-b', 'evt-c', 'evt-d', 'evt-e'];
      // No host: a sampled hit naming one becomes an observable and an observed data that the next test files count
      const hit = (eventId: string) => ({
        event_id: eventId,
        timestamp: '2026-10-05T10:00:00Z',
        matched: [{ field: 'process.command_line', value_hash: 'b'.repeat(64), value_preview: 'powershell -enc AAAA' }],
        host: null,
      });
      const runOver = async (eventIds: string[]) => {
        const started = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: knownHuntId } });
        const runId = started.data?.huntRunStart[0].id;
        await reportAsConnector({
          query: HUNT_RUN_REPORT,
          variables: {
            id: runId,
            input: { status: 'completed', hits_count: eventIds.length, hits_sample: eventIds.map(hit), hit_keys: eventIds.map((eventId) => huntHitKey(hit(eventId))) },
          },
        });
        return (await queryAsAdminWithSuccess({ query: HUNT_RUN_KNOWN_HITS, variables: { id: runId } })).data?.huntRun;
      };
      const huntSightings = () => fullRelationsList<BasicStoreRelation & { attribute_count: number; x_opencti_hunt_run_id: string }>(
        testContext,
        ADMIN_USER,
        STIX_SIGHTING_RELATIONSHIP,
        { filters: { mode: 'and', filters: [{ key: ['x_opencti_hunt_id'], values: [knownHuntId] }], filterGroups: [] } } as never,
      );
      // A first run: every hit is new, an incident draft opens, the hunt sights its technique once
      const first = await runOver(events.slice(0, 3));
      if (first.draft_id) {
        draftIds.push(first.draft_id);
      }
      expect(first).toMatchObject({ hits_count: 3, hits_new_count: 3, hits_recurring_count: 0, hits_identified: true, incident_continued: false, sightings_created_count: 1 });
      expect(first.incident_id).toBeTruthy();
      expect(first.hits_sample.map((sampled: { is_new: boolean }) => sampled.is_new)).toEqual([true, true, true]);
      const [sighting] = await huntSightings();
      expect(sighting).toMatchObject({ attribute_count: 3, x_opencti_hunt_run_id: first.id });
      // A second run over the same events: nothing is new, nothing escalates, the same sighting stays
      const second = await runOver(events.slice(0, 3));
      expect(second).toMatchObject({ hits_count: 3, hits_new_count: 0, hits_recurring_count: 3, hits_identified: true, sightings_created_count: 0 });
      expect(second.incident_id).toBeNull();
      expect(second.hits_sample.map((sampled: { is_new: boolean; times_seen: number }) => [sampled.is_new, sampled.times_seen])).toEqual([[false, 2], [false, 2], [false, 2]]);
      const afterSecond = await huntSightings();
      expect(afterSecond).toHaveLength(1);
      expect(afterSecond[0]).toMatchObject({ id: sighting.id, attribute_count: 3, x_opencti_hunt_run_id: second.id });
      // A third run with two new hits: they reach the threshold and go to the incident still open, the sighting counts 5
      const third = await runOver([events[0], events[3], events[4]]);
      expect(third).toMatchObject({ hits_new_count: 2, hits_recurring_count: 1, incident_continued: true, incident_id: first.incident_id, draft_id: first.draft_id });
      const afterThird = await huntSightings();
      expect(afterThird).toHaveLength(1);
      expect(afterThird[0]).toMatchObject({ id: sighting.id, attribute_count: 5 });
      const read = await queryAsAdminWithSuccess({ query: HUNT_KNOWN_HITS, variables: { id: knownHuntId } });
      expect(read.data?.hunt).toMatchObject({ last_hits_count: 3, last_new_hits_count: 2, knownHits: { distinct_count: 5 } });
    } finally {
      // The next tests count the hunts of the technique: this one leaves
      await queryAsAdmin({ query: HUNT_DELETE, variables: { id: knownHuntId } });
    }
  });

  it('should translate without executing for a preview', async () => {
    const preview = await queryAsAdminWithSuccess({ query: HUNT_TEST_QUERY, variables: { id: huntId } });
    const run = preview.data?.huntTestQuery;
    expect(run.hunt_run_mode).toEqual('preview');
    expect(run.hunt_run_trigger).toEqual('preview');
    const reported = await reportAsConnector({
      query: HUNT_RUN_REPORT,
      variables: { id: run.id, input: { status: 'completed', translated_query: 'index=edr CommandLine="* -enc *"', query_language: 'spl', hits_count: 99 } },
    });
    expect(reported.data?.huntRunReport.translated_query).toEqual('index=edr CommandLine="* -enc *"');
    // Previews never count hits nor get a verdict
    expect(reported.data?.huntRunReport.hits_count).toBeNull();
    expect(reported.data?.huntRunReport.verdict).toEqual('pending');
  });

  it('should list the runs of the hunt and compute its statistics on executed runs', async () => {
    const runs = await queryAsAdminWithSuccess({ query: HUNT_RUNS, variables: { filters: runFilters(huntId) } });
    const modes = runs.data?.huntRuns.edges.map((edge: { node: { hunt_run_mode: string } }) => edge.node.hunt_run_mode);
    expect(modes.filter((mode: string) => mode === 'execute')).toHaveLength(2);
    expect(modes.filter((mode: string) => mode === 'preview')).toHaveLength(2);
    const statistics = await queryAsAdminWithSuccess({ query: HUNT_STATISTICS, variables: { huntId } });
    expect(statistics.data?.huntStatistics).toMatchObject({ runs_count: 2, completed_runs_count: 2, hits_total: 9, benign_count: 0, true_positive_count: 1 });
    expect(statistics.data?.huntStatistics.runs_per_platform).toEqual([{ label: SECURITY_PLATFORM_NAME, value: 2 }]);
  });

  it('should record a run its connector stopped at the deadline as a timeout and plan its retry', async () => {
    const runs = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: huntId } });
    const runId = runs.data?.huntRunStart[0].id;
    await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: runId, input: { status: 'running' } } });
    const reported = await reportAsConnector({
      query: HUNT_RUN_REPORT,
      variables: { id: runId, input: { status: 'timeout', error: 'The hunt run exceeded its deadline of 300 seconds', cost_ms: 300000 } },
    });
    const run = reported.data?.huntRunReport;
    expect(run.hunt_run_status).toEqual('timeout');
    expect(run.error_message).toEqual('The hunt run exceeded its deadline of 300 seconds');
    expect(run.next_retry_at).toBeTruthy();
    expect(run.hits_count ?? 0).toEqual(0);
  });

  it('should record a completed run without hits in partial results as inconclusive, not benign', async () => {
    const runs = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: huntId } });
    const runId = runs.data?.huntRunStart[0].id;
    const reported = await reportAsConnector({
      query: HUNT_RUN_REPORT,
      variables: { id: runId, input: { status: 'completed', hits_count: 0, truncated: true } },
    });
    expect(reported.data?.huntRunReport).toMatchObject({ hunt_run_status: 'completed', results_truncated: true, verdict: 'inconclusive', verdict_source: 'auto' });
  });

  it('should record a completed run without hits whose connector did not state its completeness as inconclusive', async () => {
    const runs = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: huntId } });
    const runId = runs.data?.huntRunStart[0].id;
    const reported = await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: runId, input: { status: 'completed', hits_count: 0 } } });
    // Unknown is kept as unknown, never read as complete
    expect(reported.data?.huntRunReport).toMatchObject({ hunt_run_status: 'completed', results_truncated: null, verdict: 'inconclusive', verdict_source: 'auto' });
  });

  it('should record a run that sent more result objects than a run keeps as partial results', async () => {
    const runs = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: huntId } });
    const runId = runs.data?.huntRunStart[0].id;
    // A run keeps at least as many result objects as the results a hunt may request
    expect(HUNT_RUN_RESULT_IDS_MAX).toBeGreaterThanOrEqual(HUNT_CONFIG.maxResultsPerRun);
    const resultIds = Array.from({ length: HUNT_RUN_RESULT_IDS_MAX + 1 }, (_, index) => `indicator--00000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`);
    const reported = await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: runId, input: { status: 'completed', hits_count: 0, result_ids: resultIds } } });
    // Its Results drawer and its playbooks miss objects: the run is never presented as complete
    expect(reported.data?.huntRunReport).toMatchObject({ hunt_run_status: 'completed', results_truncated: true, verdict: 'inconclusive' });
    const stored = await internalLoadById<BasicStoreEntity & { result_ids?: string[] }>(testContext, ADMIN_USER, runId, { type: ENTITY_TYPE_HUNT_RUN });
    expect(stored.result_ids).toHaveLength(HUNT_RUN_RESULT_IDS_MAX);
  });

  it('should never record a hunt as queued over a run its connector completed during the dispatch', async () => {
    const statistics = vi.spyOn(huntStats, 'updateHuntRunInformation');
    try {
      const runs = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: huntId } });
      const runId = runs.data?.huntRunStart[0].id;
      const queuedCall = statistics.mock.calls.find(([, id, patch]) => id === huntId && patch.last_run_status === 'queued');
      expect(queuedCall).toBeTruthy();
      const [, , queuedPatch, queuedOptions] = queuedCall as Parameters<typeof huntStats.updateHuntRunInformation>;
      expect(queuedOptions).toEqual({ onlyIfNewer: true });
      // The queued date is taken before the run is published
      const stored = await internalLoadById<BasicStoreEntity>(testContext, ADMIN_USER, runId, { type: ENTITY_TYPE_HUNT_RUN });
      expect(Date.parse(queuedPatch.last_run_at as string)).toBeLessThanOrEqual(Date.parse(stored.created_at as unknown as string));
      // A fast connector completes the run first: the queued write landing afterwards changes nothing
      await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: runId, input: { status: 'completed', hits_count: 0 } } });
      await huntStats.updateHuntRunInformation(testContext, huntId, queuedPatch, queuedOptions);
      const hunt = await queryAsAdminWithSuccess({ query: HUNT_READ, variables: { id: huntId } });
      expect(hunt.data?.hunt.last_run_status).toEqual('completed');
    } finally {
      statistics.mockRestore();
    }
  });

  it('should export a self-describing hunt pack and import it back as a hub draft', async () => {
    const pack = await queryAsAdminWithSuccess({ query: HUNT_PACK_EXPORT, variables: { ids: [huntId] } });
    const bundle = JSON.parse(pack.data?.huntPackExport);
    expect(bundle.type).toEqual('bundle');
    const types = bundle.objects.map((object: { type: string }) => object.type);
    expect(types).toEqual(expect.arrayContaining(['extension-definition', 'hunt', 'attack-pattern', 'intrusion-set']));
    expect(bundle.objects.find((object: { id: string }) => object.id === STIX_EXT_OCTI_HUNT)).toBeTruthy();
    const exported = bundle.objects.find((object: { type: string }) => object.type === 'hunt');
    expect(exported.hunt_status).toEqual('draft');
    expect(exported.hunt_source_kind).toEqual('hub');
    const toUpload = (content: object) => Promise.resolve({
      filename: 'hunt-pack.json',
      mimetype: 'application/json',
      encoding: 'utf-8',
      createReadStream: () => Readable.from([Buffer.from(JSON.stringify(content))]),
    } as any);
    // Importing the pack of a hunt that exists here updates its definition, never how it runs here
    const sameHunt = await importHuntPack(testContext, ADMIN_USER, toUpload(bundle));
    expect(sameHunt.hunts.map((hunt) => hunt.internal_id)).toEqual([huntId]);
    expect({ created: sameHunt.created_count, updated: sameHunt.updated_count }).toEqual({ created: 0, updated: 1 });
    const unchanged = await queryAsAdminWithSuccess({ query: HUNT_READ, variables: { id: huntId } });
    expect(unchanged.data?.hunt.hunt_status).toEqual('active');
    expect(unchanged.data?.hunt.hunt_source_kind).toEqual('analyst');
    // The name is the identity of a hunt: the same hunt under another STIX ID is still the hunt that exists here
    const otherStixId = {
      ...bundle,
      objects: bundle.objects.map((object: { type: string }) => (object.type === 'hunt' ? { ...object, id: 'hunt--2b8f6c3e-9a1d-5c4b-8e7f-1a2b3c4d5e6f' } : object)),
    };
    const sameName = await importHuntPack(testContext, ADMIN_USER, toUpload(otherStixId));
    expect(sameName.hunts.map((hunt) => hunt.internal_id)).toEqual([huntId]);
    expect({ created: sameName.created_count, updated: sameName.updated_count }).toEqual({ created: 0, updated: 1 });
    const stillLocal = await queryAsAdminWithSuccess({ query: HUNT_READ, variables: { id: huntId } });
    expect(stillLocal.data?.hunt.hunt_status).toEqual('active');
    expect(stillLocal.data?.hunt.hunt_source_kind).toEqual('analyst');
    // A new hunt of a pack lands in draft with the hub origin
    const renamed = {
      ...bundle,
      objects: bundle.objects.map((object: { type: string }) => (object.type === 'hunt' ? { ...object, id: 'hunt--5d1c0a5a-6e0f-5a8f-9d3c-6b8b3f7f0a01', name: 'Hunt test pack hunt' } : object)),
    };
    const imported = await importHuntPack(testContext, ADMIN_USER, toUpload(renamed));
    expect(imported.hunts).toHaveLength(1);
    expect({ created: imported.created_count, updated: imported.updated_count }).toEqual({ created: 1, updated: 0 });
    const [newHunt] = imported.hunts;
    huntIds.push(newHunt.internal_id);
    expect(newHunt.hunt_status).toEqual('draft');
    expect(newHunt.hunt_source_kind).toEqual('hub');
    const draftRun = await queryAsAdmin({ query: HUNT_RUN_START, variables: { id: newHunt.internal_id } });
    expect(draftRun.errors?.[0].message).toContain('does not run');
    // A hunt whose markings are unknown here is skipped without creating its labels
    const blockedLabel = 'hunt-test-blocked-pack-label';
    const blocked = {
      ...bundle,
      objects: bundle.objects.map((object: { type: string }) => (object.type === 'hunt' ? {
        ...object,
        id: 'hunt--7a2e4c1b-3d5f-5e6a-8b9c-0d1e2f3a4b5c',
        name: 'Hunt test blocked pack hunt',
        labels: [blockedLabel],
        object_marking_refs: ['marking-definition--0b7c4a2e-5d1f-4e3a-9c8b-7a6f5e4d3c2b'],
      } : object)),
    };
    const skipped = await importHuntPack(testContext, ADMIN_USER, toUpload(blocked));
    expect(skipped.hunts).toHaveLength(0);
    expect(skipped.unresolved_refs).toContain('marking-definition--0b7c4a2e-5d1f-4e3a-9c8b-7a6f5e4d3c2b');
    const labels = await queryAsAdminWithSuccess({
      query: gql`query HuntPackLabels($search: String) { labels(search: $search) { edges { node { value } } } }`,
      variables: { search: blockedLabel },
    });
    expect(labels.data?.labels.edges.map((edge: { node: { value: string } }) => edge.node.value)).not.toContain(blockedLabel);
    // A pack whose last hunt is refused fails as a whole: the hunts before it and their labels are not written
    const atomicLabel = 'hunt-test-atomic-pack-label';
    const atomicHuntId = 'hunt--9c3d5e7f-1a2b-5c4d-8e6f-7a8b9c0d1e2f';
    const atomic = {
      ...bundle,
      objects: [
        ...bundle.objects.filter((object: { type: string }) => object.type !== 'hunt'),
        { ...exported, id: atomicHuntId, name: 'Hunt test atomic pack hunt', labels: [atomicLabel] },
        { ...exported, id: 'hunt--1b2c3d4e-5f6a-5b7c-9d8e-0f1a2b3c4d5e', name: 'Hunt test refused pack hunt', sigma_rule: 'title: [x' },
      ],
    };
    await expect(importHuntPack(testContext, ADMIN_USER, toUpload(atomic))).rejects.toThrow('Invalid Sigma rule');
    const notWritten = await queryAsAdmin({ query: HUNT_READ, variables: { id: atomicHuntId } });
    expect(notWritten.data?.hunt).toBeNull();
    const atomicLabels = await queryAsAdminWithSuccess({
      query: gql`query HuntPackLabels($search: String) { labels(search: $search) { edges { node { value } } } }`,
      variables: { search: atomicLabel },
    });
    expect(atomicLabels.data?.labels.edges.map((edge: { node: { value: string } }) => edge.node.value)).not.toContain(atomicLabel);
    // Two hunts of one pack with the same name would be one hunt here: the pack is refused, nothing is written
    const duplicated = {
      ...bundle,
      objects: [
        ...bundle.objects.filter((object: { type: string }) => object.type !== 'hunt'),
        { ...exported, id: atomicHuntId, name: 'Hunt test duplicated pack hunt' },
        { ...exported, id: 'hunt--3c4d5e6f-7a8b-5c9d-8e0f-1a2b3c4d5e6f', name: 'Hunt test duplicated pack hunt' },
      ],
    };
    await expect(importHuntPack(testContext, ADMIN_USER, toUpload(duplicated))).rejects.toThrow('A hunt pack cannot hold two hunts with the same name');
    const duplicateNotWritten = await queryAsAdmin({ query: HUNT_READ, variables: { id: atomicHuntId } });
    expect(duplicateNotWritten.data?.hunt).toBeNull();
    // A pack hunt named like a hunt this user cannot read is refused before the first write
    const restrictedName = 'Hunt test restricted pack hunt';
    const restrictedPack = await importHuntPack(testContext, ADMIN_USER, toUpload({
      ...bundle,
      objects: [
        ...bundle.objects.filter((object: { type: string }) => object.type !== 'hunt'),
        { ...exported, id: 'hunt--4d5e6f7a-8b9c-5d0e-9f1a-2b3c4d5e6f7a', name: restrictedName, object_marking_refs: [MARKING_TLP_RED] },
      ],
    }));
    huntIds.push(...restrictedPack.hunts.map((hunt) => hunt.internal_id));
    expect(restrictedPack.created_count).toEqual(1);
    const editor = await getAuthUser(USER_EDITOR.id);
    const editorPack = {
      ...bundle,
      objects: [
        ...bundle.objects.filter((object: { type: string }) => object.type !== 'hunt'),
        { ...exported, id: atomicHuntId, name: 'Hunt test editor pack hunt', object_marking_refs: [] },
        { ...exported, id: 'hunt--5e6f7a8b-9c0d-5e1f-8a2b-3c4d5e6f7a8b', name: restrictedName, object_marking_refs: [] },
      ],
    };
    await expect(importHuntPack(testContext, editor, toUpload(editorPack))).rejects.toThrow('Restricted entity already exists');
    const editorNotWritten = await queryAsAdmin({ query: HUNT_READ, variables: { id: atomicHuntId } });
    expect(editorNotWritten.data?.hunt).toBeNull();
  });

  it('should validate hunts from an OpenAEV emulation, idempotently per inject', async () => {
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue(undefined);
    const input = {
      technique_id: TECHNIQUE_MITRE_ID,
      security_platform_name: SECURITY_PLATFORM_NAME,
      inject_id: 'hunt-test-inject',
      window_start: new Date(Date.now() - 3600 * 1000).toISOString(),
      window_end: new Date().toISOString(),
    };
    // Two deliveries of the same inject at once (OpenAEV retries) start one run, not two
    const [first, concurrent] = await Promise.all([
      queryAsAdminWithSuccess({ query: HUNT_VALIDATE_EMULATION, variables: { input } }),
      queryAsAdminWithSuccess({ query: HUNT_VALIDATE_EMULATION, variables: { input } }),
    ]);
    const validation = first.data?.huntValidateFromEmulation;
    expect(validation.hunts_count).toEqual(1);
    expect(validation.runs).toHaveLength(1);
    expect(validation.runs[0]).toMatchObject({ hunt_run_trigger: 'emulation', aev_inject_id: 'hunt-test-inject', technique_id: techniqueId });
    expect(concurrent.data?.huntValidateFromEmulation.runs.map((run: { id: string }) => run.id)).toEqual([validation.runs[0].id]);
    emulationRunId = validation.runs[0].id;
    const second = await queryAsAdminWithSuccess({ query: HUNT_VALIDATE_EMULATION, variables: { input } });
    expect(second.data?.huntValidateFromEmulation.runs.map((run: { id: string }) => run.id)).toEqual([validation.runs[0].id]);
    const invalidWindow = await queryAsAdmin({ query: HUNT_VALIDATE_EMULATION, variables: { input: { ...input, window_start: input.window_end } } });
    expect(invalidWindow.errors?.[0].message).toContain('The emulation window is invalid');
    // A coverage that cannot be found is refused: its runs would validate nothing it ever receives
    const unknownCoverage = await queryAsAdmin({
      query: HUNT_VALIDATE_EMULATION,
      variables: { input: { ...input, inject_id: 'hunt-test-unknown-coverage-inject', security_coverage_id: 'security-coverage--00000000-0000-4000-8000-000000000000' } },
    });
    expect(unknownCoverage.errors?.[0].message).toContain('The security coverage of the emulation cannot be found');
  });

  it('should compute the validation of each technique over all its emulation runs', async () => {
    const query = gql`query HuntTechniqueValidations($id: String!) { hunt(id: $id) { techniqueValidations { technique_id status emulation_runs_count detected_runs_count } } }`;
    const pending = await queryAsAdminWithSuccess({ query, variables: { id: huntId } });
    expect(pending.data?.hunt.techniqueValidations).toEqual([
      { technique_id: techniqueId, status: 'in_progress', emulation_runs_count: 1, detected_runs_count: 0 },
    ]);
    const runTechnique = await queryAsAdminWithSuccess({
      query: gql`query HuntRunTechnique($id: String!) { huntRun(id: $id) { technique_id technique { id x_mitre_id } } }`,
      variables: { id: emulationRunId },
    });
    expect(runTechnique.data?.huntRun).toEqual({ technique_id: techniqueId, technique: { id: techniqueId, x_mitre_id: TECHNIQUE_MITRE_ID } });
    await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: emulationRunId, input: { status: 'completed', hits_count: 2 } } });
    const validated = await queryAsAdminWithSuccess({ query, variables: { id: huntId } });
    expect(validated.data?.hunt.techniqueValidations).toEqual([
      { technique_id: techniqueId, status: 'validated', emulation_runs_count: 1, detected_runs_count: 1 },
    ]);
  });

  it('should write the hunt efficacy of an emulation on each security coverage from its own runs only', async () => {
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue(undefined);
    const coverages: BasicStoreEntity[] = [];
    const coveredRelationIds: string[] = [];
    const huntDetected = async (relationId: string) => {
      const relation = await internalLoadById<BasicStoreEntity & { coverage_information?: { coverage_name: string; coverage_score: number }[] }>(
        testContext,
        ADMIN_USER,
        relationId,
        { type: RELATION_HAS_COVERED },
      );
      return relation.coverage_information?.find((information) => information.coverage_name === 'hunt_detected')?.coverage_score;
    };
    // A security coverage is identified by the object it covers: two coverages cover two objects
    const otherCovered = await addIntrusionSet(testContext, ADMIN_USER, { name: 'Hunt test second covered intrusion set' });
    const coveredIds = [intrusionSetStandardId, otherCovered.standard_id];
    try {
      for (let index = 0; index < coveredIds.length; index += 1) {
        const coverage = await addSecurityCoverage(testContext, ADMIN_USER, {
          name: `Hunt test coverage ${index}`,
          objectCovered: coveredIds[index],
          auto_enrichment_disable: true,
          external_uri: `http://openaev.local/hunt-test/scenarios/${index}`,
        });
        coverages.push(coverage);
        const [result] = await listSecurityCoverageResults(testContext, ADMIN_USER, coverage);
        const relation = await createRelation(testContext, ADMIN_USER, {
          relationship_type: RELATION_HAS_COVERED,
          fromId: result.id,
          toId: techniqueId,
          coverage_information: [{ coverage_name: 'detection', coverage_score: 50 }],
        });
        coveredRelationIds.push(relation.id);
      }
      // The same inject validated for two security coverages: each one gets its own run
      const input = {
        technique_id: TECHNIQUE_MITRE_ID,
        security_platform_name: SECURITY_PLATFORM_NAME,
        inject_id: 'hunt-test-coverage-inject',
        window_start: new Date(Date.now() - 3600 * 1000).toISOString(),
        window_end: new Date().toISOString(),
      };
      const runIds: string[] = [];
      for (let index = 0; index < coverages.length; index += 1) {
        const validation = await queryAsAdminWithSuccess({ query: HUNT_VALIDATE_EMULATION, variables: { input: { ...input, security_coverage_id: coverages[index].id } } });
        expect(validation.data?.huntValidateFromEmulation.runs).toHaveLength(1);
        runIds.push(validation.data?.huntValidateFromEmulation.runs[0].id);
      }
      expect(new Set(runIds).size).toEqual(2);
      // Hits on the run of the first coverage only
      await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: runIds[0], input: { status: 'completed', hits_count: 2 } } });
      await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: runIds[1], input: { status: 'completed', hits_count: 0 } } });
      expect(await huntDetected(coveredRelationIds[0])).toEqual(100);
      expect(await huntDetected(coveredRelationIds[1])).toEqual(0);
    } finally {
      for (let index = 0; index < coverages.length; index += 1) {
        await securityCoverageDelete(testContext, ADMIN_USER, coverages[index].standard_id);
      }
      await deleteElementById(testContext, ADMIN_USER, otherCovered.id, ENTITY_TYPE_INTRUSION_SET);
    }
  });

  it('should target only the security platforms the user starting a run can read, and restrict each run like its platform', async () => {
    const restrictedPlatform = await addSecurityPlatform(testContext, ADMIN_USER, {
      name: 'Hunt test restricted platform',
      security_platform_type: 'SIEM',
      objectMarking: [MARKING_TLP_RED],
    }) as BasicStoreEntity;
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REGISTER_CONNECTOR,
      variables: { input: { id: RESTRICTED_CONNECTOR_ID, name: 'Hunt test restricted connector', type: 'INTERNAL_HUNT', scope: ['splunk'], auto: false, only_contextual: false } },
    });
    await patchAttribute(testContext, ADMIN_USER, RESTRICTED_CONNECTOR_ID, ENTITY_TYPE_CONNECTOR, {
      hunt_platform: 'splunk',
      hunt_languages: ['spl'],
      hunt_security_platform_id: restrictedPlatform.internal_id,
      hunt_supports_preview: true,
    });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    const startedRunIds: string[] = [];
    try {
      // The editor cannot read the TLP:RED platform: a run without platform targets only the readable one
      const editorRuns = await queryAsUserWithSuccess(USER_EDITOR, { query: HUNT_RUN_START, variables: { id: huntId } });
      startedRunIds.push(...(editorRuns.data?.huntRunStart ?? []).map((run: { id: string }) => run.id));
      expect(editorRuns.data?.huntRunStart.map((run: { security_platform_id: string }) => run.security_platform_id)).toEqual([securityPlatformId]);
      await queryAsUserIsExpectedError(
        USER_EDITOR,
        { query: HUNT_RUN_START, variables: { id: huntId, input: { security_platform_ids: [restrictedPlatform.internal_id] } } },
        'No live hunt connector serves a security platform of this hunt you can access',
      );
      await queryAsUserIsExpectedError(
        USER_EDITOR,
        { query: HUNT_TEST_QUERY, variables: { id: huntId, securityPlatformId: restrictedPlatform.internal_id } },
        'No live hunt connector supporting translation preview serves a platform you can access',
      );
      // A hunt planned for explicit platforms is scoped to them: each must resolve for the user planning it
      await expect(resolveHuntPlanPlatformIds(testContext, await getAuthUser(USER_EDITOR.id), [securityPlatformId, restrictedPlatform.internal_id]))
        .rejects.toThrow('A security platform the hunt is planned for cannot be found');
      const planned = await resolveHuntPlanPlatformIds(testContext, ADMIN_USER, [restrictedPlatform.standard_id, restrictedPlatform.internal_id, securityPlatformId]);
      expect(planned).toEqual([restrictedPlatform.internal_id, securityPlatformId]);
      // A run on the platform carries its marking, so it stays hidden from the users who cannot read the platform
      const adminRuns = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: huntId, input: { security_platform_ids: [restrictedPlatform.internal_id] } } });
      const [restrictedRun] = adminRuns.data?.huntRunStart ?? [];
      startedRunIds.push(restrictedRun.id);
      expect(restrictedRun.connector_id).toEqual(RESTRICTED_CONNECTOR_ID);
      const hidden = await queryAsUserWithSuccess(USER_EDITOR, { query: HUNT_RUN_READ, variables: { id: restrictedRun.id } });
      expect(hidden.data?.huntRun).toBeNull();
      const visible = await queryAsAdminWithSuccess({ query: HUNT_RUN_READ, variables: { id: restrictedRun.id } });
      expect(visible.data?.huntRun.id).toEqual(restrictedRun.id);
    } finally {
      for (let index = 0; index < startedRunIds.length; index += 1) {
        await deleteElementById(testContext, ADMIN_USER, startedRunIds[index], ENTITY_TYPE_HUNT_RUN);
      }
      await queryAsAdmin({ query: gql`mutation DeleteConnector($id: ID!) { deleteConnector(id: $id) }`, variables: { id: RESTRICTED_CONNECTOR_ID } });
      await deleteElementById(testContext, ADMIN_USER, restrictedPlatform.internal_id, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    }
  });

  it('should keep a run unfinalized while a finalization step fails, then complete it', async () => {
    const started = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: huntId, input: { security_platform_ids: [securityPlatformId] } } });
    const runId = started.data?.huntRunStart[0].id;
    const statistics = vi.spyOn(huntStats, 'updateHuntRunInformation').mockRejectedValueOnce(new Error('engine unavailable'));
    const reported = await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: runId, input: { status: 'completed', hits_count: 0, truncated: false } } });
    statistics.mockRestore();
    // No verdict recorded: the run is not finalized while its statistics are missing
    expect(reported.data?.huntRunReport).toMatchObject({ hunt_run_status: 'completed', verdict: 'pending', verdict_source: null });
    await patchAttribute(testContext, HUNT_MANAGER_USER, runId, ENTITY_TYPE_HUNT_RUN, { completed_at: new Date(Date.now() - 10 * 60000).toISOString() });
    expect(await finalizeInterruptedHuntRuns(testContext)).toBeGreaterThanOrEqual(1);
    const run = (await queryAsAdminWithSuccess({ query: HUNT_RUN_STATE, variables: { id: runId } })).data?.huntRun;
    expect(run).toMatchObject({ verdict: 'benign', verdict_source: 'auto' });
  });

  it('should complete a pending finalization before recording a verdict', async () => {
    const started = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: huntId, input: { security_platform_ids: [securityPlatformId] } } });
    const runId = started.data?.huntRunStart[0].id;
    const statistics = vi.spyOn(huntStats, 'updateHuntRunInformation').mockRejectedValue(new Error('engine unavailable'));
    try {
      await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: runId, input: { status: 'completed', hits_count: 0 } } });
      // While a step keeps failing the verdict is refused: the run stays unfinalized for the hunt manager to retry
      const refused = await queryAsAdmin({ query: HUNT_RUN_VERDICT, variables: { id: runId, input: { verdict: 'benign' } } });
      expect(refused.errors?.[0].message).toContain('still being finalized');
      const pending = (await queryAsAdminWithSuccess({ query: HUNT_RUN_STATE, variables: { id: runId } })).data?.huntRun;
      expect(pending).toMatchObject({ verdict: 'pending', verdict_source: null });
    } finally {
      statistics.mockRestore();
    }
    // Once the step succeeds, the verdict completes the finalization first, then records the analyst verdict
    const verdict = await queryAsAdminWithSuccess({ query: HUNT_RUN_VERDICT, variables: { id: runId, input: { verdict: 'benign', hunt_analyst_feedback: 'Checked' } } });
    expect(verdict.data?.huntRunSetVerdict).toMatchObject({ verdict: 'benign', verdict_source: 'analyst' });
  });

  it('should record a verdict as the agent one only when it applies the verdict the agent proposed', async () => {
    const started = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: huntId, input: { security_platform_ids: [securityPlatformId] } } });
    const runId = started.data?.huntRunStart[0].id;
    await reportAsConnector({ query: HUNT_RUN_REPORT, variables: { id: runId, input: { status: 'completed', hits_count: 0 } } });
    const setVerdict = async (verdict: string) => {
      const result = await queryAsAdminWithSuccess({ query: HUNT_RUN_VERDICT, variables: { id: runId, input: { verdict, source: 'agent' } } });
      return result.data?.huntRunSetVerdict;
    };
    // No proposal on the run: the verdict is the decision of the analyst who sets it, whatever the client says
    expect(await setVerdict('inconclusive')).toMatchObject({ verdict: 'inconclusive', verdict_source: 'analyst' });
    await patchAttribute(testContext, HUNT_MANAGER_USER, runId, ENTITY_TYPE_HUNT_RUN, { verdict_proposal: 'inconclusive' });
    expect(await setVerdict('inconclusive')).toMatchObject({ verdict: 'inconclusive', verdict_source: 'agent' });
    // Another verdict than the proposal is not the agent's
    expect(await setVerdict('benign')).toMatchObject({ verdict: 'benign', verdict_source: 'analyst' });
  });

  it('should delete a hunt', async () => {
    const pack = huntIds.pop() as string;
    const deleted = await queryAsAdminWithSuccess({ query: HUNT_DELETE, variables: { id: pack } });
    expect(deleted.data?.huntDelete).toEqual(pack);
    const read = await queryAsAdminWithSuccess({ query: HUNT_READ, variables: { id: pack } });
    expect(read.data?.hunt).toBeNull();
  });
});
