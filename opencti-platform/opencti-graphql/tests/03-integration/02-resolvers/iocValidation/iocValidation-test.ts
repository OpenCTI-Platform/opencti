import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedError, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_CONNECTOR, USER_EDITOR } from '../../../utils/testQuery';
import { connectorDelete, registerConnector } from '../../../../src/domain/connector';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { ENTITY_TYPE_CONNECTOR } from '../../../../src/schema/internalObject';
import { ConnectorType } from '../../../../src/generated/graphql';
import { maintainIocValidationRequests, validationResultSightingStixId } from '../../../../src/modules/iocValidation/iocValidation-domain';
import { IOC_VALIDATION_CONNECTOR_SCOPE } from '../../../../src/modules/iocValidation/iocValidation-types';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../src/schema/stixSightingRelationship';
import type { BasicStoreRelation } from '../../../../src/types/store';

const IOC_VALIDATION_CONNECTOR = '20202020-0b20-4b20-8b20-202020202020';

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
    stixCoreRelationship(id: $id) { id validation_status validation_run_id }
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
  connector { id }
  requested_by { id }
  openaev_simulation_id
  work_id
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
const REPORT_RESULTS = gql`
  mutation ReportResults($id: ID!, $platformId: StixRef!, $results: [IocValidationPairResultInput!]!) {
    iocValidationReportResults(id: $id, platformId: $platformId, results: $results) { id results_summary { total requested error skipped } }
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
    const list = await queryAsAdminWithSuccess({ query: REQUESTS_LIST, variables: {} });
    expect(list.data?.iocValidationRequests.edges.map((e: { node: { id: string } }) => e.node.id)).toContain(requestId);
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
    // Validation of the input and of the target platform
    await queryAsUserIsExpectedError(USER_CONNECTOR, {
      query: REPORT_RESULTS,
      variables: { id, platformId, results: [{ indicatorId: liveIndicatorId, status: 'missed', hitCount: 0 }] },
    });
    await queryAsUserIsExpectedError(USER_CONNECTOR, {
      query: REPORT_RESULTS,
      variables: { id, platformId: liveIndicatorId, results: [{ indicatorId: liveIndicatorId, status: 'missed' }] },
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
    // A late result never overwrites the recorded verdict
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_RESULTS,
      variables: { id, platformId, results: [{ indicatorId: liveIndicatorId, status: 'detected' }] },
    });
    const unchanged = await queryAsAdminWithSuccess({ query: DEPLOYMENT_READ, variables: { id: liveDeploymentId } });
    expect(unchanged.data?.stixCoreRelationship.validation_status).toEqual('missed');
    await queryAsAdminWithSuccess({ query: REQUEST_DELETE, variables: { id } });
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
});
