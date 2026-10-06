import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import * as streamHandler from '../../../../src/database/stream/stream-handler';
import * as rabbitmq from '../../../../src/database/rabbitmq';
import { worksForSource } from '../../../../src/domain/work';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedError, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_CONNECTOR, USER_EDITOR, USER_PARTICIPATE } from '../../../utils/testQuery';
import { RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import { connectorDelete, registerConnector } from '../../../../src/domain/connector';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { ENTITY_TYPE_CONNECTOR } from '../../../../src/schema/internalObject';
import { ConnectorType } from '../../../../src/generated/graphql';
import {
  IOC_VALIDATION_INACCESSIBLE_REASON,
  maintainIocValidationRequests,
  repairValidationRequestAccess,
  validationResultSightingStixId,
} from '../../../../src/modules/iocValidation/iocValidation-domain';
import { ENTITY_TYPE_IOC_VALIDATION_REQUEST, IOC_VALIDATION_CONNECTOR_SCOPE } from '../../../../src/modules/iocValidation/iocValidation-types';
import { internalLoadById, storeLoadById } from '../../../../src/database/middleware-loader';
import { createRelation, patchAttribute } from '../../../../src/database/middleware';
import { elDeleteElements, elUpdate } from '../../../../src/database/engine';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../src/schema/stixSightingRelationship';
import type { BasicStoreEntity, BasicStoreRelation } from '../../../../src/types/store';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { MARKING_TLP_AMBER } from '../../../../src/schema/identifier';

const IOC_VALIDATION_CONNECTOR = '20202020-0b20-4b20-8b20-202020202020';
const WAITING_IOC_VALIDATION_CONNECTOR = '20202020-0b20-4b20-8b20-202020202021';
// The platform refuses to recreate an id deleted moments earlier, so each offline connector test registers its own
const UNREADABLE_IOC_VALIDATION_CONNECTOR = '20202020-0b20-4b20-8b20-202020202022';
const OTHER_ACCOUNT_IOC_VALIDATION_CONNECTOR = '20202020-0b20-4b20-8b20-202020202023';
const NO_READABLE_PAIR_IOC_VALIDATION_CONNECTOR = '20202020-0b20-4b20-8b20-202020202024';
const UNPUBLISHED_IOC_VALIDATION_CONNECTOR = '20202020-0b20-4b20-8b20-202020202025';

const INDICATOR_ADD = gql`
  mutation IndicatorAdd($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) { id standard_id }
  }
`;
const INDICATOR_DELETE = gql`
  mutation IndicatorDelete($id: ID!) {
    indicatorDelete(id: $id)
  }
`;
const PLATFORM_ADD = gql`
  mutation SecurityPlatformAdd($input: SecurityPlatformAddInput!) {
    securityPlatformAdd(input: $input) { id }
  }
`;
const PLATFORM_DELETE = gql`
  mutation SecurityPlatformDelete($id: ID!) {
    securityPlatformDelete(id: $id)
  }
`;
const REPORT_DEPLOYMENT = gql`
  mutation IndicatorReportDeployment($indicatorId: StixRef!, $platformId: StixRef!, $status: IndicatorDeploymentStatus!) {
    indicatorReportDeployment(indicatorId: $indicatorId, platformId: $platformId, status: $status) { id }
  }
`;
const DEPLOYMENT_READ = gql`
  query DeploymentRead($id: String!) {
    stixCoreRelationship(id: $id) { id deployment_status validation_status validation_run_id updated_at }
  }
`;
const DEPLOYMENT_CREATORS = gql`
  query DeploymentCreators($id: String!) {
    stixCoreRelationship(id: $id) { id creators { id } }
  }
`;
const REQUEST_FIELDS = `
  id
  name
  status
  status_message
  test_kinds
  platform_ids
  indicator_ids
  platforms { id }
  indicators_count
  results_summary { total requested detected prevented missed error skipped }
  iocs { indicator_id value test_kind }
  skipped { indicator_id platform_id reason }
  deployments { id }
  pair_outcomes { deployed_on_id validation_status }
  connector { id }
  requested_by { id }
  openaev_simulation_id
  work_id
  created_at
  dispatched_at
  completed_at
`;
const REQUEST_VALIDATION = gql`
  mutation RequestValidation($platformIds: [StixRef!]!, $indicatorIds: [StixRef!]!, $testKinds: [IocValidationTestKind!]!, $connectorId: ID, $name: String) {
    indicatorsRequestValidation(platformIds: $platformIds, indicatorIds: $indicatorIds, testKinds: $testKinds, connectorId: $connectorId, name: $name) {
      ${REQUEST_FIELDS}
    }
  }
`;
const REQUEST_READ = gql`
  query RequestRead($id: String!) {
    iocValidationRequest(id: $id) { ${REQUEST_FIELDS} }
  }
`;
const REQUESTS_LIST = gql`
  query RequestsList {
    iocValidationRequests(first: 50) { edges { node { id status } } }
  }
`;
const CONNECTORS_LIST = gql`
  query IocValidationConnectors {
    iocValidationConnectors { id }
  }
`;
const STATUS_UPDATE = gql`
  mutation StatusUpdate($id: ID!, $input: IocValidationRequestStatusInput!) {
    iocValidationRequestStatusUpdate(id: $id, input: $input) { id status status_message openaev_simulation_id completed_at results_summary { total requested error skipped } }
  }
`;
const REQUESTS_FILTERED = gql`
  query RequestsFiltered($filters: FilterGroup) {
    iocValidationRequests(first: 50, filters: $filters) { edges { node { id } } }
  }
`;
const REPORT_RESULTS = gql`
  mutation ReportResults($id: ID!, $platformId: StixRef!, $results: [IocValidationPairResultInput!]!) {
    iocValidationReportResults(id: $id, platformId: $platformId, results: $results) { id results_summary { total requested error skipped } }
  }
`;
const DEPLOYMENT_FIELD_PATCH = gql`
  mutation DeploymentFieldPatch($id: ID!, $input: [EditInput]!) {
    stixCoreRelationshipEdit(id: $id) { fieldPatch(input: $input) { id } }
  }
`;
const RELATION_ADD = gql`
  mutation RelationAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) { id }
  }
`;
const SIGHTING_ADD = gql`
  mutation SightingAdd($input: StixSightingRelationshipAddInput!) {
    stixSightingRelationshipAdd(input: $input) { id }
  }
`;
const REQUEST_DELETE = gql`
  mutation RequestDelete($id: ID!) {
    iocValidationRequestDelete(id: $id)
  }
`;

describe('IOC validation requests', () => {
  let liveIndicatorId: string;
  let failedIndicatorId: string;
  let platformId: string;
  let liveDeploymentId: string;
  // Completed request with a missed verdict, kept until a newer request takes its pair over
  let provenRequestId: string;
  let requestId: string;

  beforeAll(async () => {
    const connectorUserId = await getUserIdByEmail(USER_CONNECTOR.email);
    await registerConnector(testContext, ADMIN_USER, {
      id: IOC_VALIDATION_CONNECTOR,
      name: 'OpenAEV IOC validation (requests)',
      type: ConnectorType.InternalEnrichment,
      scope: [IOC_VALIDATION_CONNECTOR_SCOPE],
      auto: false,
      auto_update: false,
    }, { active: true, connector_user_id: connectorUserId });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    const live = await queryAsAdminWithSuccess({
      query: INDICATOR_ADD,
      variables: { input: { name: 'validation.evil.example', pattern: "[domain-name:value = 'validation.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
    });
    liveIndicatorId = live.data?.indicatorAdd.id;
    const failed = await queryAsAdminWithSuccess({
      query: INDICATOR_ADD,
      variables: { input: { name: 'failed.evil.example', pattern: "[domain-name:value = 'failed.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
    });
    failedIndicatorId = failed.data?.indicatorAdd.id;
    const platform = await queryAsAdminWithSuccess({
      query: PLATFORM_ADD,
      variables: { input: { name: 'IOC validation test EDR', security_platform_type: 'EDR' } },
    });
    platformId = platform.data?.securityPlatformAdd.id;
    const deployment = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_DEPLOYMENT,
      variables: { indicatorId: liveIndicatorId, platformId, status: 'deployed' },
    });
    liveDeploymentId = deployment.data?.indicatorReportDeployment.id;
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_DEPLOYMENT,
      variables: { indicatorId: failedIndicatorId, platformId, status: 'failed' },
    });
  });

  afterAll(async () => {
    await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: liveIndicatorId } });
    await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: failedIndicatorId } });
    await queryAsAdminWithSuccess({ query: PLATFORM_DELETE, variables: { id: platformId } });
    await connectorDelete(testContext, ADMIN_USER, IOC_VALIDATION_CONNECTOR);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
  });

  it('should list the IOC validation connectors', async () => {
    const result = await queryAsAdminWithSuccess({ query: CONNECTORS_LIST, variables: {} });
    expect(result.data?.iocValidationConnectors.map((c: { id: string }) => c.id)).toContain(IOC_VALIDATION_CONNECTOR);
  });

  it('should reject invalid requests', async () => {
    const base = { platformIds: [platformId], indicatorIds: [liveIndicatorId], testKinds: ['dns_resolution'] };
    await queryAsAdminWithError({ query: REQUEST_VALIDATION, variables: { ...base, testKinds: [] } });
    await queryAsAdminWithError({ query: REQUEST_VALIDATION, variables: { ...base, name: 'n'.repeat(251) } });
    await queryAsAdminWithError({ query: REQUEST_VALIDATION, variables: { ...base, connectorId: 'not-an-ioc-validation-connector' } });
    // Only a failed deployment: nothing is live, so there is nothing to validate
    await queryAsAdminWithError({ query: REQUEST_VALIDATION, variables: { ...base, indicatorIds: [failedIndicatorId] } });
  });

  it('should dispatch the live pairs and skip the others', async () => {
    const result = await queryAsAdminWithSuccess({
      query: REQUEST_VALIDATION,
      variables: { platformIds: [platformId], indicatorIds: [liveIndicatorId, failedIndicatorId], testKinds: ['dns_resolution'], connectorId: IOC_VALIDATION_CONNECTOR },
    });
    const request = result.data?.indicatorsRequestValidation;
    requestId = request.id;
    expect(request.status).toEqual('sent');
    expect(request.work_id).toBeTruthy();
    expect(request.dispatched_at).toBeTruthy();
    expect(request.connector.id).toEqual(IOC_VALIDATION_CONNECTOR);
    expect(request.requested_by).toBeTruthy();
    expect(request.indicator_ids).toEqual([liveIndicatorId]);
    expect(request.indicators_count).toEqual(1);
    expect(request.platforms.map((p: { id: string }) => p.id)).toEqual([platformId]);
    expect(request.iocs).toEqual([{ indicator_id: liveIndicatorId, value: 'validation.evil.example', test_kind: 'dns_resolution' }]);
    expect(request.skipped.length).toEqual(1);
    expect(request.skipped[0].indicator_id).toEqual(failedIndicatorId);
    expect(request.skipped[0].reason).toContain('Not live on this security platform');
    expect(request.deployments.map((d: { id: string }) => d.id)).toEqual([liveDeploymentId]);
    expect(request.results_summary).toEqual({ total: 1, requested: 1, detected: 0, prevented: 0, missed: 0, error: 0, skipped: 1 });
    const deployment = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(deployment.data?.stixCoreRelationship.validation_status).toEqual('requested');
  });

  it('should not take over a pair waiting for another request', async () => {
    await queryAsAdminWithError({
      query: REQUEST_VALIDATION,
      variables: { platformIds: [platformId], indicatorIds: [liveIndicatorId], testKinds: ['dns_resolution'] },
    });
    const deployment = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(deployment.data?.stixCoreRelationship.validation_run_id).toEqual(requestId);
  });

  it('should read and list the request', async () => {
    const read = await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id: requestId } });
    expect(read.data?.iocValidationRequest.name).toContain('Validation of 1 indicator(s)');
    // Dated on creation: the list orders on it and the maintenance times pending requests out from it
    expect(read.data?.iocValidationRequest.created_at).toBeTruthy();
    const list = await queryAsAdminWithSuccess({ query: REQUESTS_LIST, variables: {} });
    expect(list.data?.iocValidationRequests.edges.map((e: { node: { id: string } }) => e.node.id)).toContain(requestId);
  });

  it('should give a request the access of its indicators and security platforms, and follow their changes', async () => {
    const amber = await internalLoadById(testContext, ADMIN_USER, MARKING_TLP_AMBER) as unknown as { internal_id: string };
    const platform = await internalLoadById(testContext, ADMIN_USER, platformId) as unknown as { _index: string };
    const setPlatformMarkings = async (ids: string[]) => {
      const script = { source: "ctx._source['rel_object-marking.internal_id'] = params.ids", lang: 'painless', params: { ids } };
      await elUpdate(testContext, platform._index, platformId, { script });
      await repairValidationRequestAccess(testContext, ADMIN_USER, { indicatorIds: [], platformIds: [platformId] });
    };
    const requestMarkings = async () => {
      const stored = await internalLoadById(testContext, ADMIN_USER, requestId, { type: ENTITY_TYPE_IOC_VALIDATION_REQUEST }) as unknown as Record<string, string[] | undefined>;
      return stored[RELATION_OBJECT_MARKING] ?? [];
    };
    const readAs = async (user: typeof USER_PARTICIPATE) => {
      const read = await queryAsUserWithSuccess(user, { query: REQUEST_READ, variables: { id: requestId } });
      const list = await queryAsUserWithSuccess(user, { query: REQUESTS_LIST, variables: {} });
      const listed = list.data?.iocValidationRequests.edges.some((e: { node: { id: string } }) => e.node.id === requestId);
      return { read: !!read.data?.iocValidationRequest, listed };
    };
    expect(await requestMarkings()).toEqual([]);
    expect(await readAs(USER_PARTICIPATE)).toEqual({ read: true, listed: true });
    try {
      await setPlatformMarkings([amber.internal_id]);
      expect(await requestMarkings()).toEqual([amber.internal_id]);
      // Only the readers of every end read the request: its name and OpenAEV run describe all of them
      expect(await readAs(USER_PARTICIPATE)).toEqual({ read: false, listed: false });
      expect(await readAs(USER_EDITOR)).toEqual({ read: true, listed: true });
      // The request connector reports by identity, whatever the access of the request to its account
      const approval = await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: STATUS_UPDATE,
        variables: { id: requestId, input: { status: 'awaiting_approval', message: 'Waiting for the approval of the scenario' } },
      });
      expect(approval.data?.iocValidationRequestStatusUpdate.status).toEqual('awaiting_approval');
    } finally {
      await setPlatformMarkings([]);
    }
    expect(await requestMarkings()).toEqual([]);
    expect(await readAs(USER_PARTICIPATE)).toEqual({ read: true, listed: true });
  });

  it('should only accept lifecycle updates from the request connector', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: STATUS_UPDATE,
      variables: { id: requestId, input: { status: 'running' } },
    });
    await queryAsUserIsExpectedError(USER_CONNECTOR, {
      query: STATUS_UPDATE,
      variables: { id: requestId, input: { status: 'pending' } },
    });
    const running = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: STATUS_UPDATE,
      variables: { id: requestId, input: { status: 'running', openaev_simulation_id: 'simulation-1', message: 'Simulation started' } },
    });
    expect(running.data?.iocValidationRequestStatusUpdate.status).toEqual('running');
    expect(running.data?.iocValidationRequestStatusUpdate.openaev_simulation_id).toEqual('simulation-1');
  });

  it('should keep an open request open while its pairs wait for results', async () => {
    const processed = await maintainIocValidationRequests(testContext);
    expect(processed).toBeGreaterThanOrEqual(0);
    const read = await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id: requestId } });
    expect(read.data?.iocValidationRequest.status).toEqual('running');
  });

  it('should resolve the waiting pairs as errors when OpenAEV reports a failure', async () => {
    const waiting = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    const failed = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: STATUS_UPDATE,
      variables: { id: requestId, input: { status: 'failed', message: 'No endpoint available' } },
    });
    const request = failed.data?.iocValidationRequestStatusUpdate;
    expect(request.status).toEqual('failed');
    expect(request.completed_at).toBeTruthy();
    expect(request.results_summary).toEqual({ total: 1, requested: 0, error: 1, skipped: 1 });
    const deployment = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(deployment.data?.stixCoreRelationship.validation_status).toEqual('error');
    // Incremental readers (updated_at) see the resolution, although it is written without stream event
    expect(new Date(deployment.data?.stixCoreRelationship.updated_at).getTime())
      .toBeGreaterThan(new Date(waiting.data?.stixCoreRelationship.updated_at).getTime());
    // A late lifecycle event never reopens a final request
    const late = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: STATUS_UPDATE,
      variables: { id: requestId, input: { status: 'running' } },
    });
    expect(late.data?.iocValidationRequestStatusUpdate.status).toEqual('failed');
  });

  it('should record the results a security platform proves for the pairs still waiting', async () => {
    const created = await queryAsAdminWithSuccess({
      query: REQUEST_VALIDATION,
      variables: { platformIds: [platformId], indicatorIds: [liveIndicatorId], testKinds: ['dns_resolution'], name: 'SIEM proof' },
    });
    const id = created.data?.indicatorsRequestValidation.id;
    // OpenAEV finishing before the results are ingested never makes the request final
    const finished = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: STATUS_UPDATE,
      variables: { id, input: { status: 'completed' } },
    });
    expect(finished.data?.iocValidationRequestStatusUpdate.status).toEqual('running');
    expect(finished.data?.iocValidationRequestStatusUpdate.completed_at).toBeNull();
    // Validation of the input and of the target platform
    await queryAsUserIsExpectedError(USER_CONNECTOR, {
      query: REPORT_RESULTS,
      variables: { id, platformId, results: [{ indicatorId: liveIndicatorId, status: 'missed', hitCount: 0 }] },
    });
    await queryAsUserIsExpectedError(USER_CONNECTOR, {
      query: REPORT_RESULTS,
      variables: { id, platformId: liveIndicatorId, results: [{ indicatorId: liveIndicatorId, status: 'missed' }] },
    });
    // One result per indicator, whatever ids name it: two verdicts for one pair are refused before any write
    const liveIndicator = await internalLoadById(testContext, ADMIN_USER, liveIndicatorId) as unknown as { standard_id: string };
    await queryAsUserIsExpectedError(USER_CONNECTOR, {
      query: REPORT_RESULTS,
      variables: {
        id,
        platformId,
        results: [{ indicatorId: liveIndicatorId, status: 'missed' }, { indicatorId: liveIndicator.standard_id, status: 'detected' }],
      },
    }, 'A report gives one result per indicator');
    const stillWaiting = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(stillWaiting.data?.stixCoreRelationship.validation_status).toEqual('requested');
    // Updating knowledge is not enough: only the account recording the deployments of the platform speaks for it
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: REPORT_RESULTS,
      variables: { id, platformId, results: [{ indicatorId: liveIndicatorId, status: 'detected' }] },
    });
    // A miss on the waiting pair; the skipped indicator is not a pair of the request and is ignored
    const observedAt = '2026-10-03T12:00:00.000Z';
    const reported = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_RESULTS,
      variables: {
        id,
        platformId,
        results: [
          { indicatorId: liveIndicatorId, status: 'missed', observedAt, evidence: 'No DNS query seen in the window' },
          { indicatorId: failedIndicatorId, status: 'detected' },
        ],
      },
    });
    expect(reported.data?.iocValidationReportResults.results_summary).toEqual({ total: 1, requested: 0, error: 0, skipped: 0 });
    const deployment = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(deployment.data?.stixCoreRelationship.validation_status).toEqual('missed');
    const sightingId = validationResultSightingStixId(id, liveIndicatorId, platformId);
    const sighting = await storeLoadById<BasicStoreRelation & { x_opencti_negative?: boolean; attribute_count?: number }>(
      testContext,
      ADMIN_USER,
      sightingId,
      STIX_SIGHTING_RELATIONSHIP,
    );
    expect(sighting?.x_opencti_negative).toEqual(true);
    expect(sighting?.attribute_count).toEqual(1);
    // Every pair has its result: the maintenance completes the request
    await maintainIocValidationRequests(testContext);
    const completed = await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id } });
    expect(completed.data?.iocValidationRequest.status).toEqual('completed');
    // A late result never overwrites the recorded verdict
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_RESULTS,
      variables: { id, platformId, results: [{ indicatorId: liveIndicatorId, status: 'detected' }] },
    });
    const unchanged = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(unchanged.data?.stixCoreRelationship.validation_status).toEqual('missed');
    // A sighting write lost after the verdict (removed here without event) is repaired by a retry of the same verdict
    await elDeleteElements(testContext, ADMIN_USER, [sighting as never], { forceDelete: true, forceRefresh: true });
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_RESULTS,
      variables: { id, platformId, results: [{ indicatorId: liveIndicatorId, status: 'missed', observedAt }] },
    });
    const repaired = await storeLoadById<BasicStoreRelation & { x_opencti_negative?: boolean }>(testContext, ADMIN_USER, sightingId, STIX_SIGHTING_RELATIONSHIP);
    expect(repaired?.x_opencti_negative).toEqual(true);
    provenRequestId = id;
  });

  it('should refuse validation results written outside the validation paths', async () => {
    // Generic edition: only the account that recorded the deployment, an IOC validation connector or an administrator
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: DEPLOYMENT_FIELD_PATCH,
      variables: { id: liveDeploymentId, input: [{ key: 'validation_status', value: ['detected'] }] },
    });
    // Creation or upsert carrying a verdict: only an IOC validation connector or an administrator
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: RELATION_ADD,
      variables: { input: { relationship_type: 'deployed-on', fromId: liveIndicatorId, toId: platformId, validation_status: 'prevented' } },
    });
    // Upsert of the existing deployment erasing its verdict: the edition rules apply, resets included
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: RELATION_ADD,
      variables: { input: { relationship_type: 'deployed-on', fromId: liveIndicatorId, toId: platformId, validation_status: 'not_requested', update: true } },
    });
    const deployment = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(deployment.data?.stixCoreRelationship.validation_status).toEqual('missed');
  });

  it('should not let an editor who upserted a deployment speak for the security platform', async () => {
    const editorId = await getUserIdByEmail(USER_EDITOR.email);
    // Upserting the deployment with a description only adds the editor to its creators
    await queryAsUserWithSuccess(USER_EDITOR, {
      query: RELATION_ADD,
      variables: { input: { relationship_type: 'deployed-on', fromId: liveIndicatorId, toId: platformId, description: 'Seen in the change log', update: true } },
    });
    const upserted = await queryAsAdminWithSuccess({ query: DEPLOYMENT_CREATORS, variables: { id: liveDeploymentId } });
    expect(upserted.data?.stixCoreRelationship.creators.map((creator: { id: string }) => creator.id)).toContain(editorId);
    // Being a creator is not enough to write a verdict, by edition or as a result of a request
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: DEPLOYMENT_FIELD_PATCH,
      variables: { id: liveDeploymentId, input: [{ key: 'validation_status', value: ['detected'] }] },
    });
    const created = await queryAsAdminWithSuccess({
      query: REQUEST_VALIDATION,
      variables: { platformIds: [platformId], indicatorIds: [liveIndicatorId], testKinds: ['dns_resolution'], name: 'Upserted deployment' },
    });
    const id = created.data?.indicatorsRequestValidation.id;
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: REPORT_RESULTS,
      variables: { id, platformId, results: [{ indicatorId: liveIndicatorId, status: 'detected' }] },
    });
    const waiting = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(waiting.data?.stixCoreRelationship.validation_status).toEqual('requested');
    // The earlier request keeps its own verdict while the newer one waits for its results
    const earlier = await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id: provenRequestId } });
    expect(earlier.data?.iocValidationRequest.pair_outcomes).toEqual([{ deployed_on_id: liveDeploymentId, validation_status: 'missed' }]);
    expect(earlier.data?.iocValidationRequest.results_summary).toEqual(expect.objectContaining({ missed: 1, requested: 0 }));
    const newer = await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id } });
    expect(newer.data?.iocValidationRequest.pair_outcomes).toEqual([{ deployed_on_id: liveDeploymentId, validation_status: 'requested' }]);
    await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id } });
    await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id: provenRequestId } });
  });

  it('should only filter requests on plain attributes and accessible references', async () => {
    const byPlatform = await queryAsAdminWithSuccess({
      query: REQUESTS_FILTERED,
      variables: { filters: { mode: 'and', filters: [{ key: 'platform_ids', values: [platformId] }], filterGroups: [] } },
    });
    expect(byPlatform.data?.iocValidationRequests.edges.map((e: { node: { id: string } }) => e.node.id)).toContain(requestId);
    const unknownPlatform = await queryAsAdminWithSuccess({
      query: REQUESTS_FILTERED,
      variables: { filters: { mode: 'and', filters: [{ key: 'platform_ids', values: ['identity--00000000-0000-4000-8000-000000000000'] }], filterGroups: [] } },
    });
    expect(unknownPlatform.data?.iocValidationRequests.edges).toEqual([]);
    await queryAsAdminWithError({
      query: REQUESTS_FILTERED,
      variables: { filters: { mode: 'and', filters: [{ key: 'iocs.value', values: ['validation.evil.example'] }], filterGroups: [] } },
    });
    await queryAsAdminWithError({
      query: REQUESTS_FILTERED,
      variables: { filters: { mode: 'and', filters: [{ key: 'indicator_ids', values: [liveIndicatorId], operator: 'not_eq' }], filterGroups: [] } },
    });
  });

  it('should release the waiting pairs when a request is deleted', async () => {
    const result = await queryAsAdminWithSuccess({
      query: REQUEST_VALIDATION,
      variables: { platformIds: [platformId], indicatorIds: [liveIndicatorId], testKinds: ['dns_resolution'], name: 'To delete' },
    });
    const id = result.data?.indicatorsRequestValidation.id;
    const requested = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(requested.data?.stixCoreRelationship.validation_status).toEqual('requested');
    const deleted = await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id } });
    expect(deleted.data?.iocValidationRequestDelete).toEqual(id);
    const read = await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id } });
    expect(read.data?.iocValidationRequest).toBeNull();
    const released = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(released.data?.stixCoreRelationship.validation_status).toEqual('not_requested');
    await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id: requestId } });
  });

  it('should only send the pairs still live when a request waited for its connector', async () => {
    const connectorUserId = await getUserIdByEmail(USER_CONNECTOR.email);
    const waitingConnector = {
      id: WAITING_IOC_VALIDATION_CONNECTOR,
      name: 'OpenAEV IOC validation (offline)',
      type: ConnectorType.InternalEnrichment,
      scope: [IOC_VALIDATION_CONNECTOR_SCOPE],
      auto: false,
      auto_update: false,
    };
    await registerConnector(testContext, ADMIN_USER, waitingConnector, { connector_user_id: connectorUserId });
    // A registered connector is alive while it pings: its last ping is set beyond the liveness window
    const offline = await storeLoadById<BasicStoreEntity>(testContext, ADMIN_USER, WAITING_IOC_VALIDATION_CONNECTOR, ENTITY_TYPE_CONNECTOR);
    await elUpdate(testContext, offline._index, offline.internal_id, { doc: { updated_at: new Date(Date.now() - 10 * 60 * 1000).toISOString() } });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    const indicator = await queryAsAdminWithSuccess({
      query: INDICATOR_ADD,
      variables: { input: { name: 'waiting.evil.example', pattern: "[domain-name:value = 'waiting.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
    });
    const indicatorId = indicator.data?.indicatorAdd.id;
    try {
      const deployment = await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: REPORT_DEPLOYMENT,
        variables: { indicatorId, platformId, status: 'deployed' },
      });
      const deploymentId = deployment.data?.indicatorReportDeployment.id;
      const created = await queryAsAdminWithSuccess({
        query: REQUEST_VALIDATION,
        variables: { platformIds: [platformId], indicatorIds: [indicatorId], testKinds: ['dns_resolution'], connectorId: WAITING_IOC_VALIDATION_CONNECTOR, name: 'Waiting for its connector' },
      });
      const request = created.data?.indicatorsRequestValidation;
      expect(request.status).toEqual('pending');
      expect(request.status_message).toEqual('Waiting for an active OpenAEV IOC validation connector');
      // The platform removes the indicator while the request waits, then the connector comes back
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_DEPLOYMENT, variables: { indicatorId, platformId, status: 'removed' } });
      // The connector pings again
      await registerConnector(testContext, ADMIN_USER, waitingConnector, { connector_user_id: connectorUserId });
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
      await maintainIocValidationRequests(testContext);
      const read = await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id: request.id } });
      const dispatched = read.data?.iocValidationRequest;
      expect(dispatched.status).toEqual('failed');
      expect(dispatched.work_id).toBeNull();
      expect(dispatched.skipped).toEqual([{ indicator_id: indicatorId, platform_id: platformId, reason: 'Not live on this security platform' }]);
      expect(dispatched.results_summary).toEqual(expect.objectContaining({ total: 0, requested: 0, skipped: 1 }));
      const released = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: deploymentId } });
      expect(released.data?.stixCoreRelationship.validation_status).toEqual('not_requested');
      expect(released.data?.stixCoreRelationship.validation_run_id).toBeNull();
      await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id: request.id } });
    } finally {
      await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: indicatorId } });
      await connectorDelete(testContext, ADMIN_USER, WAITING_IOC_VALIDATION_CONNECTOR);
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    }
  });

  it('should leave out before dispatch the pairs the OpenAEV service account can no longer read', async () => {
    const connectorUserId = await getUserIdByEmail(USER_CONNECTOR.email);
    const waitingConnector = {
      id: UNREADABLE_IOC_VALIDATION_CONNECTOR,
      name: 'OpenAEV IOC validation (offline, markings changed)',
      type: ConnectorType.InternalEnrichment,
      scope: [IOC_VALIDATION_CONNECTOR_SCOPE],
      auto: false,
      auto_update: false,
    };
    await registerConnector(testContext, ADMIN_USER, waitingConnector, { connector_user_id: connectorUserId });
    const offline = await storeLoadById<BasicStoreEntity>(testContext, ADMIN_USER, UNREADABLE_IOC_VALIDATION_CONNECTOR, ENTITY_TYPE_CONNECTOR);
    await elUpdate(testContext, offline._index, offline.internal_id, { doc: { updated_at: new Date(Date.now() - 10 * 60 * 1000).toISOString() } });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    const hidden = await queryAsAdminWithSuccess({
      query: INDICATOR_ADD,
      variables: { input: { name: 'hidden.evil.example', pattern: "[domain-name:value = 'hidden.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
    });
    const hiddenId = hidden.data?.indicatorAdd.id;
    let partialRequestId: string | undefined;
    try {
      const deployment = await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_DEPLOYMENT, variables: { indicatorId: hiddenId, platformId, status: 'deployed' } });
      const hiddenDeploymentId = deployment.data?.indicatorReportDeployment.id;
      const created = await queryAsAdminWithSuccess({
        query: REQUEST_VALIDATION,
        variables: {
          platformIds: [platformId],
          indicatorIds: [liveIndicatorId, hiddenId],
          testKinds: ['dns_resolution'],
          connectorId: UNREADABLE_IOC_VALIDATION_CONNECTOR,
          name: 'Partly readable by OpenAEV',
        },
      });
      partialRequestId = created.data?.indicatorsRequestValidation.id;
      expect(created.data?.indicatorsRequestValidation.status).toEqual('pending');
      // While the request waits, the indicator gets a marking the OpenAEV service account cannot read (no stream event)
      const amber = await internalLoadById(testContext, ADMIN_USER, MARKING_TLP_AMBER) as unknown as { internal_id: string };
      const stored = await internalLoadById(testContext, ADMIN_USER, hiddenId) as unknown as { _index: string };
      const script = { source: "ctx._source['rel_object-marking.internal_id'] = params.ids", lang: 'painless', params: { ids: [amber.internal_id] } };
      await elUpdate(testContext, stored._index, hiddenId, { script });
      // The connector pings again
      await registerConnector(testContext, ADMIN_USER, waitingConnector, { connector_user_id: connectorUserId });
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
      await maintainIocValidationRequests(testContext);
      const read = await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id: partialRequestId } });
      const dispatched = read.data?.iocValidationRequest;
      expect(dispatched.status).toEqual('sent');
      expect(dispatched.deployments.map((d: { id: string }) => d.id)).toEqual([liveDeploymentId]);
      expect(dispatched.skipped).toEqual([{ indicator_id: hiddenId, platform_id: platformId, reason: IOC_VALIDATION_INACCESSIBLE_REASON }]);
      // The pair left out does not wait for this request any more
      const released = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: hiddenDeploymentId } });
      expect(released.data?.stixCoreRelationship.validation_status).toEqual('not_requested');
    } finally {
      if (partialRequestId) {
        await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id: partialRequestId } });
      }
      await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: hiddenId } });
      await connectorDelete(testContext, ADMIN_USER, UNREADABLE_IOC_VALIDATION_CONNECTOR);
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    }
  });

  it('should fail a request none of whose pairs the OpenAEV service account can read, with the outcome of each pair', async () => {
    const connectorUserId = await getUserIdByEmail(USER_CONNECTOR.email);
    const waitingConnector = {
      id: NO_READABLE_PAIR_IOC_VALIDATION_CONNECTOR,
      name: 'OpenAEV IOC validation (offline, nothing readable)',
      type: ConnectorType.InternalEnrichment,
      scope: [IOC_VALIDATION_CONNECTOR_SCOPE],
      auto: false,
      auto_update: false,
    };
    await registerConnector(testContext, ADMIN_USER, waitingConnector, { connector_user_id: connectorUserId });
    const offline = await storeLoadById<BasicStoreEntity>(testContext, ADMIN_USER, NO_READABLE_PAIR_IOC_VALIDATION_CONNECTOR, ENTITY_TYPE_CONNECTOR);
    await elUpdate(testContext, offline._index, offline.internal_id, { doc: { updated_at: new Date(Date.now() - 10 * 60 * 1000).toISOString() } });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    const hidden = await queryAsAdminWithSuccess({
      query: INDICATOR_ADD,
      variables: { input: { name: 'unreadable.evil.example', pattern: "[domain-name:value = 'unreadable.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
    });
    const hiddenId = hidden.data?.indicatorAdd.id;
    let requestId: string | undefined;
    try {
      const deployment = await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_DEPLOYMENT, variables: { indicatorId: hiddenId, platformId, status: 'deployed' } });
      const hiddenDeploymentId = deployment.data?.indicatorReportDeployment.id;
      const created = await queryAsAdminWithSuccess({
        query: REQUEST_VALIDATION,
        variables: {
          platformIds: [platformId],
          indicatorIds: [hiddenId],
          testKinds: ['dns_resolution'],
          connectorId: NO_READABLE_PAIR_IOC_VALIDATION_CONNECTOR,
          name: 'Unreadable by OpenAEV',
        },
      });
      requestId = created.data?.indicatorsRequestValidation.id;
      expect(created.data?.indicatorsRequestValidation.results_summary).toMatchObject({ total: 1, requested: 1, error: 0 });
      // While the request waits, its only indicator gets a marking the OpenAEV service account cannot read (no stream event)
      const amber = await internalLoadById(testContext, ADMIN_USER, MARKING_TLP_AMBER) as unknown as { internal_id: string };
      const stored = await internalLoadById(testContext, ADMIN_USER, hiddenId) as unknown as { _index: string };
      const script = { source: "ctx._source['rel_object-marking.internal_id'] = params.ids", lang: 'painless', params: { ids: [amber.internal_id] } };
      await elUpdate(testContext, stored._index, hiddenId, { script });
      await registerConnector(testContext, ADMIN_USER, waitingConnector, { connector_user_id: connectorUserId });
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
      await maintainIocValidationRequests(testContext);
      const read = await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id: requestId } });
      const failed = read.data?.iocValidationRequest;
      expect(failed.status).toEqual('failed');
      expect(failed.completed_at).toBeTruthy();
      // The failed request records the outcome of its pair, as a request failed by OpenAEV does
      expect(failed.results_summary).toMatchObject({ total: 1, requested: 0, error: 1 });
      expect(failed.pair_outcomes).toEqual([{ deployed_on_id: hiddenDeploymentId, validation_status: 'error' }]);
      const outcome = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: hiddenDeploymentId } });
      expect(outcome.data?.stixCoreRelationship.validation_status).toEqual('error');
    } finally {
      if (requestId) {
        await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id: requestId } });
      }
      await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: hiddenId } });
      await connectorDelete(testContext, ADMIN_USER, NO_READABLE_PAIR_IOC_VALIDATION_CONNECTOR);
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    }
  });

  it('should close the work of a request in error when it cannot be published, before the request is dispatched again', async () => {
    // Writes outside the dataset: kept out of the raw stream the synchronization tests count
    const streamed = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
    ];
    const connectorUserId = await getUserIdByEmail(USER_CONNECTOR.email);
    const waitingConnector = {
      id: UNPUBLISHED_IOC_VALIDATION_CONNECTOR,
      name: 'OpenAEV IOC validation (queue unavailable)',
      type: ConnectorType.InternalEnrichment,
      scope: [IOC_VALIDATION_CONNECTOR_SCOPE],
      auto: false,
      auto_update: false,
    };
    await registerConnector(testContext, ADMIN_USER, waitingConnector, { connector_user_id: connectorUserId });
    const offline = await storeLoadById<BasicStoreEntity>(testContext, ADMIN_USER, UNPUBLISHED_IOC_VALIDATION_CONNECTOR, ENTITY_TYPE_CONNECTOR);
    await elUpdate(testContext, offline._index, offline.internal_id, { doc: { updated_at: new Date(Date.now() - 10 * 60 * 1000).toISOString() } });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    const publish = rabbitmq.pushToConnector;
    let id: string | undefined;
    try {
      const created = await queryAsAdminWithSuccess({
        query: REQUEST_VALIDATION,
        variables: { platformIds: [platformId], indicatorIds: [liveIndicatorId], testKinds: ['dns_resolution'], connectorId: UNPUBLISHED_IOC_VALIDATION_CONNECTOR, name: 'Queue unavailable' },
      });
      id = created.data?.indicatorsRequestValidation.id as string;
      expect(created.data?.indicatorsRequestValidation.status).toEqual('pending');
      // The connector is alive again, but its queue refuses the request
      await registerConnector(testContext, ADMIN_USER, waitingConnector, { connector_user_id: connectorUserId });
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
      const refused = vi.spyOn(rabbitmq, 'pushToConnector').mockImplementation(async (connectorId: string, message: unknown) => {
        if (connectorId === UNPUBLISHED_IOC_VALIDATION_CONNECTOR) {
          throw new Error('Queue unavailable');
        }
        return publish(connectorId, message as never);
      });
      try {
        await maintainIocValidationRequests(testContext);
      } finally {
        refused.mockRestore();
      }
      const released = (await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id } })).data?.iocValidationRequest;
      expect(released).toMatchObject({ status: 'pending', work_id: null, dispatched_at: null });
      const [closed] = await worksForSource(testContext, SYSTEM_USER, id) as unknown as Array<{ id: string; status: string; errors: Array<{ message: string; source: string }> }>;
      expect(closed.status).toEqual('complete');
      expect(closed.errors).toEqual([expect.objectContaining({ message: 'The request could not be published to the queue of the connector', source: 'Platform' })]);
      // The next scan dispatches the request with a new work
      await maintainIocValidationRequests(testContext);
      const sent = (await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id } })).data?.iocValidationRequest;
      expect(sent.status).toEqual('sent');
      expect(sent.work_id).toBeTruthy();
      expect(sent.work_id).not.toEqual(closed.id);
      const works = await worksForSource(testContext, SYSTEM_USER, id) as unknown as Array<{ id: string }>;
      expect(works.map((work) => work.id).sort()).toEqual([closed.id, sent.work_id].sort());
    } finally {
      if (id) {
        await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id } });
      }
      await connectorDelete(testContext, ADMIN_USER, UNPUBLISHED_IOC_VALIDATION_CONNECTOR);
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
      streamed.forEach((spy) => spy.mockRestore());
    }
  });

  it('should let a late verdict of the request replace only the outcome its timeout set', async () => {
    const created = await queryAsAdminWithSuccess({
      query: REQUEST_VALIDATION,
      variables: { platformIds: [platformId], indicatorIds: [liveIndicatorId], testKinds: ['dns_resolution'], name: 'Timed out' },
    });
    const id = created.data?.indicatorsRequestValidation.id;
    // Dispatched long ago without any answer: the maintenance times it out
    await patchAttribute(testContext, SYSTEM_USER, id, ENTITY_TYPE_IOC_VALIDATION_REQUEST, { dispatched_at: new Date('2020-01-01T00:00:00.000Z') });
    await maintainIocValidationRequests(testContext);
    const expired = await queryAsAdminWithSuccess({ query: REQUEST_READ, variables: { id } });
    expect(expired.data?.iocValidationRequest.status).toEqual('expired');
    const timedOut = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(timedOut.data?.stixCoreRelationship.validation_status).toEqual('error');
    // The platform proves the test after the timeout: the verdict replaces the timeout error and gets its sighting
    const late = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_RESULTS,
      variables: { id, platformId, results: [{ indicatorId: liveIndicatorId, status: 'detected' }] },
    });
    expect(late.data?.iocValidationReportResults.results_summary).toEqual({ total: 1, requested: 0, error: 0, skipped: 0 });
    const replaced = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(replaced.data?.stixCoreRelationship.validation_status).toEqual('detected');
    const sighting = await storeLoadById(testContext, ADMIN_USER, validationResultSightingStixId(id, liveIndicatorId, platformId), STIX_SIGHTING_RELATIONSHIP);
    expect(sighting).toBeTruthy();
    // A recorded verdict is never replaced, even of a request that timed out
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_RESULTS,
      variables: { id, platformId, results: [{ indicatorId: liveIndicatorId, status: 'missed' }] },
    });
    const kept = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(kept.data?.stixCoreRelationship.validation_status).toEqual('detected');
    // The result sightings go with their request: none is left outside the access repair of the pair
    await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id } });
    const deletedSighting = await storeLoadById(testContext, ADMIN_USER, validationResultSightingStixId(id, liveIndicatorId, platformId), STIX_SIGHTING_RELATIONSHIP);
    expect(deletedSighting).toBeFalsy();
  });

  it('should refuse a result whose sighting identifier is taken by a sighting that does not record it', async () => {
    // Writes outside the dataset: kept out of the raw stream the synchronization tests count
    const streamed = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
    ];
    let id: string | undefined;
    try {
      const created = await queryAsAdminWithSuccess({
        query: REQUEST_VALIDATION,
        variables: { platformIds: [platformId], indicatorIds: [liveIndicatorId], testKinds: ['dns_resolution'], name: 'Collision' },
      });
      id = created.data?.indicatorsRequestValidation.id as string;
      // A positive sighting created beforehand under the deterministic id of the result
      await createRelation(testContext, ADMIN_USER, {
        fromId: liveIndicatorId,
        toId: platformId,
        relationship_type: STIX_SIGHTING_RELATIONSHIP,
        stix_id: validationResultSightingStixId(id, liveIndicatorId, platformId),
        x_opencti_negative: false,
      });
      await queryAsUserIsExpectedError(USER_CONNECTOR, {
        query: REPORT_RESULTS,
        variables: { id, platformId, results: [{ indicatorId: liveIndicatorId, status: 'missed' }] },
      });
      const deployment = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
      expect(deployment.data?.stixCoreRelationship.validation_status).toEqual('requested');
    } finally {
      if (id) {
        await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id } });
      }
      streamed.forEach((spy) => spy.mockRestore());
    }
  });

  it('should reserve the result sighting identifier of a running validation to the accounts reporting it', async () => {
    let id: string | undefined;
    try {
      const created = await queryAsAdminWithSuccess({
        query: REQUEST_VALIDATION,
        variables: { platformIds: [platformId], indicatorIds: [liveIndicatorId], testKinds: ['dns_resolution'], name: 'Reserved' },
      });
      id = created.data?.indicatorsRequestValidation.id as string;
      const reservedId = validationResultSightingStixId(id, liveIndicatorId, platformId);
      await queryAsUserIsExpectedForbidden(USER_EDITOR, {
        query: SIGHTING_ADD,
        variables: { input: { fromId: liveIndicatorId, toId: platformId, stix_id: reservedId, attribute_count: 1, x_opencti_negative: false } },
      });
      await queryAsUserIsExpectedForbidden(USER_EDITOR, {
        query: SIGHTING_ADD,
        variables: { input: { fromId: liveIndicatorId, toId: platformId, x_opencti_stix_ids: [reservedId], attribute_count: 1, x_opencti_negative: false } },
      });
      const squatted = await storeLoadById(testContext, ADMIN_USER, reservedId, STIX_SIGHTING_RELATIONSHIP);
      expect(squatted).toBeFalsy();
    } finally {
      if (id) {
        await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id } });
      }
    }
  });

  it('should leave the expired status to the deployment manager on every write path', async () => {
    await queryAsUserIsExpectedError(USER_CONNECTOR, {
      query: DEPLOYMENT_FIELD_PATCH,
      variables: { id: liveDeploymentId, input: [{ key: 'deployment_status', value: ['expired'] }] },
    });
    await queryAsUserIsExpectedError(USER_CONNECTOR, {
      query: RELATION_ADD,
      variables: { input: { relationship_type: 'deployed-on', fromId: liveIndicatorId, toId: platformId, deployment_status: 'expired', update: true } },
    });
    const deployment = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(deployment.data?.stixCoreRelationship.deployment_status).toEqual('deployed');
  });

  it('should leave the result sighting of an earlier request to the accounts reporting it after a newer request took the pair over', async () => {
    // Writes outside the dataset: kept out of the raw stream the synchronization tests count
    const streamed = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
    ];
    let olderId: string | undefined;
    let newerId: string | undefined;
    try {
      const older = await queryAsAdminWithSuccess({
        query: REQUEST_VALIDATION,
        variables: { platformIds: [platformId], indicatorIds: [liveIndicatorId], testKinds: ['dns_resolution'], name: 'Older' },
      });
      olderId = older.data?.indicatorsRequestValidation.id as string;
      await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: REPORT_RESULTS,
        variables: { id: olderId, platformId, results: [{ indicatorId: liveIndicatorId, status: 'detected' }] },
      });
      // The result sighting of the older request is lost (removed here without event): its identifier is free again
      const olderResultId = validationResultSightingStixId(olderId, liveIndicatorId, platformId);
      const olderSighting = await storeLoadById(testContext, ADMIN_USER, olderResultId, STIX_SIGHTING_RELATIONSHIP);
      await elDeleteElements(testContext, ADMIN_USER, [olderSighting as never], { forceDelete: true, forceRefresh: true });
      const newer = await queryAsAdminWithSuccess({
        query: REQUEST_VALIDATION,
        variables: { platformIds: [platformId], indicatorIds: [liveIndicatorId], testKinds: ['dns_resolution'], name: 'Newer' },
      });
      newerId = newer.data?.indicatorsRequestValidation.id as string;
      const deployment = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
      expect(deployment.data?.stixCoreRelationship.validation_run_id).toEqual(newerId);
      // The pair is bound to the newer request now: the older result stays with the accounts reporting it
      await queryAsUserIsExpectedForbidden(USER_EDITOR, {
        query: SIGHTING_ADD,
        variables: { input: { fromId: liveIndicatorId, toId: platformId, stix_id: olderResultId, attribute_count: 1, x_opencti_negative: true } },
      });
      expect(await storeLoadById(testContext, ADMIN_USER, olderResultId, STIX_SIGHTING_RELATIONSHIP)).toBeFalsy();
    } finally {
      for (const id of [newerId, olderId]) {
        if (id) {
          await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id } });
        }
      }
      streamed.forEach((spy) => spy.mockRestore());
    }
  });

  it('should answer the results of the account recording the deployments with the request as that account reads it', async () => {
    // Writes outside the dataset: kept out of the raw stream the synchronization tests count
    const streamed = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
    ];
    // Sent to the connector of another account: the connector account here only recorded the deployments
    await registerConnector(testContext, ADMIN_USER, {
      id: OTHER_ACCOUNT_IOC_VALIDATION_CONNECTOR,
      name: 'OpenAEV IOC validation (another account)',
      type: ConnectorType.InternalEnrichment,
      scope: [IOC_VALIDATION_CONNECTOR_SCOPE],
      auto: false,
      auto_update: false,
    }, { active: true, connector_user_id: ADMIN_USER.id });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    let restrictedIndicatorId: string | undefined;
    let id: string | undefined;
    try {
      const restricted = await queryAsAdminWithSuccess({
        query: INDICATOR_ADD,
        variables: { input: { name: 'restricted.evil.example', pattern: "[domain-name:value = 'restricted.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
      });
      restrictedIndicatorId = restricted.data?.indicatorAdd.id as string;
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_DEPLOYMENT, variables: { indicatorId: restrictedIndicatorId, platformId, status: 'deployed' } });
      // Side-channel marking: the request covers an indicator the connector account does not read
      const amber = await internalLoadById(testContext, ADMIN_USER, MARKING_TLP_AMBER) as unknown as { internal_id: string };
      const stored = await internalLoadById(testContext, ADMIN_USER, restrictedIndicatorId) as unknown as { _index: string };
      const script = { source: "ctx._source['rel_object-marking.internal_id'] = params.ids", lang: 'painless', params: { ids: [amber.internal_id] } };
      await elUpdate(testContext, stored._index, restrictedIndicatorId, { script });
      const created = await queryAsAdminWithSuccess({
        query: REQUEST_VALIDATION,
        variables: {
          platformIds: [platformId],
          indicatorIds: [liveIndicatorId, restrictedIndicatorId],
          testKinds: ['dns_resolution'],
          connectorId: OTHER_ACCOUNT_IOC_VALIDATION_CONNECTOR,
          name: 'Sent to another account',
        },
      });
      id = created.data?.indicatorsRequestValidation.id as string;
      const read = await queryAsUserWithSuccess(USER_CONNECTOR, { query: REQUEST_READ, variables: { id } });
      expect(read.data?.iocValidationRequest).toBeNull();
      // Its result for the pair it recorded is accepted, and the response does not show the request
      const reported = await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: REPORT_RESULTS,
        variables: { id, platformId, results: [{ indicatorId: liveIndicatorId, status: 'detected' }] },
      });
      expect(reported.data?.iocValidationReportResults).toBeNull();
      const deployment = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
      expect(deployment.data?.stixCoreRelationship.validation_status).toEqual('detected');
      expect(deployment.data?.stixCoreRelationship.validation_run_id).toEqual(id);
    } finally {
      if (id) {
        await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id } });
      }
      if (restrictedIndicatorId) {
        await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: restrictedIndicatorId } });
      }
      await connectorDelete(testContext, ADMIN_USER, OTHER_ACCOUNT_IOC_VALIDATION_CONNECTOR);
      resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
      streamed.forEach((spy) => spy.mockRestore());
    }
  });
});
