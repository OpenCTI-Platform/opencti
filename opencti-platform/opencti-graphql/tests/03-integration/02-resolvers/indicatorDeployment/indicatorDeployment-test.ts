import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedError, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER, getUserIdByEmail, PLATFORM_ORGANIZATION, TEST_ORGANIZATION, testContext, USER_CONNECTOR, USER_EDITOR, USER_PARTICIPATE } from '../../../utils/testQuery';
import {
  backfillIndicatorDeploymentCounters,
  COUNTER_FIELDS,
  findDeployedOn,
  flagExpiredDeployments,
  reconcileAllIndicatorDeploymentCounters,
  reconcileDeployedIndicatorCounters,
  reconcileIndicatorDeploymentCounters,
  recordIndicatorRevocations,
  refreshIndicatorDeploymentCounters,
  repairPairMarkings,
} from '../../../../src/modules/indicatorDeployment/indicatorDeployment-domain';
import { hitsSightingStixId } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-utils';
import { createRelation, deleteElementById, stixLoadById } from '../../../../src/database/middleware';
import * as middleware from '../../../../src/database/middleware';
import { internalLoadById } from '../../../../src/database/middleware-loader';
import { elDeleteElements, elUpdate } from '../../../../src/database/engine';
import * as streamHandler from '../../../../src/database/stream/stream-handler';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../src/schema/stixSightingRelationship';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import { MARKING_TLP_AMBER } from '../../../../src/schema/identifier';

const INDICATOR_ADD = gql`
  mutation IndicatorAdd($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) { id standard_id }
  }
`;
const INDICATOR_READ = gql`
  query IndicatorRead($id: String!) {
    indicator(id: $id) {
      id
      deployments_count
      deployment_platforms_count
      deployment_failed_count
      deployment_expired_count
      validated_platforms_count
      hit_platforms_count
    }
  }
`;
const INDICATOR_DELETE = gql`
  mutation IndicatorDelete($id: ID!) {
    indicatorDelete(id: $id)
  }
`;
const PLATFORM_ADD = gql`
  mutation SecurityPlatformAdd($input: SecurityPlatformAddInput!) {
    securityPlatformAdd(input: $input) { id standard_id name }
  }
`;
const PLATFORM_DELETE = gql`
  mutation SecurityPlatformDelete($id: ID!) {
    securityPlatformDelete(id: $id)
  }
`;
const DEPLOYMENT_FIELDS = `
  id
  relationship_type
  revoked
  deployment_status
  external_id
  deployed_at
  last_sync_at
  removed_at
  hit_count
  first_hit_at
  last_hit_at
  validation_status
  error_message
`;
const RELATION_ADD = gql`
  mutation DeployedOnAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) { ${DEPLOYMENT_FIELDS} }
  }
`;
const DEPLOYMENT_MARKING_DELETE = gql`
  mutation DeploymentMarkingDelete($id: ID!, $toId: StixRef!) {
    stixCoreRelationshipEdit(id: $id) { relationDelete(toId: $toId, relationship_type: "object-marking") { id } }
  }
`;
const SIGHTING_MARKING_DELETE = gql`
  mutation SightingMarkingDelete($id: ID!, $toId: StixRef!) {
    stixSightingRelationshipEdit(id: $id) { relationDelete(toId: $toId, relationship_type: "object-marking") { id } }
  }
`;
const SIGHTING_FIELD_PATCH = gql`
  mutation SightingFieldPatch($id: ID!, $input: [EditInput]!) {
    stixSightingRelationshipEdit(id: $id) { fieldPatch(input: $input) { id } }
  }
`;
const SIGHTING_ADD = gql`
  mutation SightingAdd($input: StixSightingRelationshipAddInput!) {
    stixSightingRelationshipAdd(input: $input) { id }
  }
`;
const DEPLOYMENT_FIELD_PATCH = gql`
  mutation DeploymentFieldPatch($id: ID!, $input: [EditInput]!) {
    stixCoreRelationshipEdit(id: $id) { fieldPatch(input: $input) { id } }
  }
`;
const REPORT_DEPLOYMENT = gql`
  mutation IndicatorReportDeployment($indicatorId: StixRef!, $platformId: StixRef!, $status: IndicatorDeploymentStatus!, $externalId: String, $metadata: IndicatorDeploymentMetadataInput) {
    indicatorReportDeployment(indicatorId: $indicatorId, platformId: $platformId, status: $status, externalId: $externalId, metadata: $metadata) {
      ${DEPLOYMENT_FIELDS}
    }
  }
`;
const REPORT_DEPLOYMENTS = gql`
  mutation IndicatorReportDeployments($platformId: StixRef!, $reports: [IndicatorDeploymentReportInput!]!) {
    indicatorReportDeployments(platformId: $platformId, reports: $reports) {
      processed created updated unchanged
      errors { indicatorId message }
    }
  }
`;
const REPORT_HITS = gql`
  mutation IndicatorReportHits($indicatorId: StixRef!, $platformId: StixRef!, $count: Int!, $lastHit: DateTime, $firstHit: DateTime, $reportId: String) {
    indicatorReportHits(indicatorId: $indicatorId, platformId: $platformId, count: $count, lastHit: $lastHit, firstHit: $firstHit, reportId: $reportId) {
      id
      attribute_count
      first_seen
      last_seen
      x_opencti_negative
    }
  }
`;
const DEPLOYMENT_RETRY = gql`
  mutation IndicatorDeploymentRetry($id: ID!) {
    indicatorDeploymentRetry(id: $id) { ${DEPLOYMENT_FIELDS} }
  }
`;
const DEPLOYMENT_REMOVE = gql`
  mutation IndicatorDeploymentRemove($id: ID!) {
    indicatorDeploymentRemove(id: $id) { ${DEPLOYMENT_FIELDS} }
  }
`;
const DEPLOYMENTS_LIST = gql`
  query Deployments($toId: [String], $filters: FilterGroup) {
    stixCoreRelationships(relationship_type: ["deployed-on"], toId: $toId, filters: $filters, first: 50) {
      edges { node { ${DEPLOYMENT_FIELDS} } }
    }
  }
`;
const DEPLOYMENT_HITS_READ = gql`
  query DeploymentHits($fromId: [String], $toId: [String]) {
    stixCoreRelationships(relationship_type: ["deployed-on"], fromId: $fromId, toId: $toId, first: 1) {
      edges { node { id last_hit_at last_hit_report_ids } }
    }
  }
`;
const METRICS = gql`
  query Metrics($platformId: String) {
    disseminationAssuranceMetrics(platformId: $platformId) {
      funnel { created disseminated deployed validated hit expired_still_deployed }
      deployment_statuses { status count }
      validation_statuses { status count }
      failures_by_platform { platform { id name } count }
      deployments_by_platform { platform { id name } count }
      proven_share
    }
  }
`;

describe('Indicator deployment write-back (dissemination assurance)', () => {
  let indicatorId: string;
  let indicatorStandardId: string;
  let secondIndicatorId: string;
  let platformId: string;
  let deploymentId: string;
  let testOrganizationId: string;
  let platformOrganizationId: string;

  // Side-channel sharing (no stream event, so the raw stream counts of the suite are unchanged).
  const setOrganizations = async (id: string, organizationIds: string[]) => {
    const stored = await internalLoadById(testContext, ADMIN_USER, id) as unknown as { _index: string };
    const script = { source: "ctx._source['rel_granted.internal_id'] = params.ids", lang: 'painless', params: { ids: organizationIds } };
    await elUpdate(testContext, stored._index, id, { script });
  };
  const setMarkings = async (id: string, markingIds: string[]) => {
    const stored = await internalLoadById(testContext, ADMIN_USER, id) as unknown as { _index: string };
    const script = { source: "ctx._source['rel_object-marking.internal_id'] = params.ids", lang: 'painless', params: { ids: markingIds } };
    await elUpdate(testContext, stored._index, id, { script });
  };
  // The deployment manager repairs a pair a moment after the events of the previous tests. The pair relationships are
  // marked before their indicator and unmarked after it, so they are never less strict than the indicator: a repair
  // landing at any time writes nothing (a marking stricter than the ends is kept), and the raw stream counts are unchanged.
  const markPairAndIndicator = async (pairIds: string[], markingIds: string[]) => {
    await Promise.all(pairIds.map((id) => setMarkings(id, markingIds)));
    await setMarkings(indicatorId, markingIds);
  };
  const unmarkIndicatorAndPair = async (pairIds: string[]) => {
    await setMarkings(indicatorId, []);
    await Promise.all(pairIds.map((id) => setMarkings(id, [])));
  };
  const loadOrganizations = async (id: string, type?: string) => {
    const element = await internalLoadById(testContext, ADMIN_USER, id, type ? { type } : undefined) as unknown as Record<string, string[] | undefined>;
    return [...(element[RELATION_GRANTED_TO] ?? [])].sort();
  };
  // The deployment manager repairs the sharing of a pair from its ends a moment after the events of the previous tests.
  // A test letting the editor read the pair therefore adds its organization rather than swapping it in, so a repair
  // landing meanwhile keeps the deployment readable by the connector account, and shares the pair again from its ends
  // once they are restored.
  const lendPairToEditor = async (sightingId: string) => {
    await setOrganizations(platformId, [platformOrganizationId, testOrganizationId]);
    await setOrganizations(sightingId, [platformOrganizationId, testOrganizationId]);
  };
  const sharePairFromItsEnds = () => repairPairMarkings(testContext, ADMIN_USER, { indicatorIds: [], platformIds: [platformId] });

  beforeAll(async () => {
    const indicator = await queryAsAdminWithSuccess({
      query: INDICATOR_ADD,
      variables: { input: { name: 'deployment.evil.example', pattern: "[domain-name:value = 'deployment.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name', x_opencti_detection: true } },
    });
    indicatorId = indicator.data?.indicatorAdd.id;
    indicatorStandardId = indicator.data?.indicatorAdd.standard_id;
    const second = await queryAsAdminWithSuccess({
      query: INDICATOR_ADD,
      variables: { input: { name: '198.51.100.77', pattern: "[ipv4-addr:value = '198.51.100.77']", pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } },
    });
    secondIndicatorId = second.data?.indicatorAdd.id;
    const platform = await queryAsAdminWithSuccess({
      query: PLATFORM_ADD,
      variables: { input: { name: 'Deployment test SIEM', security_platform_type: 'SIEM' } },
    });
    platformId = platform.data?.securityPlatformAdd.id;
    const loadInternalId = async (standardId: string) => (await internalLoadById(testContext, ADMIN_USER, standardId) as unknown as { internal_id: string }).internal_id;
    testOrganizationId = await loadInternalId(TEST_ORGANIZATION.id);
    platformOrganizationId = await loadInternalId(PLATFORM_ORGANIZATION.id);
    // The indicator is shared with two organizations, its security platform with one of them only
    await setOrganizations(indicatorId, [testOrganizationId, platformOrganizationId]);
    await setOrganizations(platformId, [testOrganizationId]);
  });

  afterAll(async () => {
    await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: indicatorId } });
    await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: secondIndicatorId } });
    await queryAsAdminWithSuccess({ query: PLATFORM_DELETE, variables: { id: platformId } });
  });

  it('should create the deployed-on relationship on the first report', async () => {
    const result = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_DEPLOYMENT,
      variables: { indicatorId: indicatorStandardId, platformId, status: 'deployed', externalId: 'ti-1' },
    });
    const deployment = result.data?.indicatorReportDeployment;
    deploymentId = deployment.id;
    expect(deployment.relationship_type).toEqual('deployed-on');
    expect(deployment.deployment_status).toEqual('deployed');
    expect(deployment.external_id).toEqual('ti-1');
    expect(deployment.deployed_at).toBeDefined();
    expect(deployment.last_sync_at).toBeDefined();
    expect(deployment.hit_count).toEqual(0);
    expect(deployment.validation_status).toEqual('not_requested');
  });

  it('should share a deployment with the organizations of both its ends only', async () => {
    // Never with the organizations of the reporting account, nor with an organization of one end only
    expect(await loadOrganizations(deploymentId)).toEqual([testOrganizationId]);
  });

  it('should keep the sharing of a deployment when an upsert names other organizations', async () => {
    // Not streamed: the raw stream counts of the suite are unchanged
    const streamed = vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never);
    try {
      await queryAsAdminWithSuccess({
        query: RELATION_ADD,
        variables: { input: { fromId: indicatorId, toId: platformId, relationship_type: 'deployed-on', objectOrganization: [platformOrganizationId], update: true } },
      });
      expect(await loadOrganizations(deploymentId)).toEqual([testOrganizationId]);
    } finally {
      streamed.mockRestore();
    }
  });

  it('should share a deployment created through the generic relationship creation with the organizations of both its ends only', async () => {
    // Neither streamed nor kept: the raw stream counts of the suite are unchanged
    const streamed = vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never);
    await setOrganizations(secondIndicatorId, [testOrganizationId, platformOrganizationId]);
    let relationId: string | undefined;
    try {
      // Requested for an organization of one end only: the deployment gets the organizations both ends are shared with
      const result = await queryAsAdminWithSuccess({
        query: RELATION_ADD,
        variables: { input: { fromId: secondIndicatorId, toId: platformId, relationship_type: 'deployed-on', objectOrganization: [platformOrganizationId] } },
      });
      relationId = result.data?.stixCoreRelationshipAdd.id;
      expect(streamed).toHaveBeenCalledTimes(1);
      expect(await loadOrganizations(relationId as string)).toEqual([testOrganizationId]);
    } finally {
      streamed.mockRestore();
      if (relationId) {
        const relation = await internalLoadById(testContext, ADMIN_USER, relationId);
        await elDeleteElements(testContext, ADMIN_USER, [relation as never], { forceDelete: true, forceRefresh: true });
      }
      await setOrganizations(secondIndicatorId, []);
    }
  });

  it('should refuse an edit removing from a deployment a marking of its indicator, through every edit path', async () => {
    const amber = await internalLoadById(testContext, ADMIN_USER, MARKING_TLP_AMBER) as unknown as { internal_id: string };
    await markPairAndIndicator([deploymentId], [amber.internal_id]);
    try {
      // The marking given by its standard id, as a client may
      await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: DEPLOYMENT_MARKING_DELETE, variables: { id: deploymentId, toId: MARKING_TLP_AMBER } });
      await queryAsUserIsExpectedForbidden(USER_EDITOR, {
        query: DEPLOYMENT_FIELD_PATCH,
        variables: { id: deploymentId, input: [{ key: 'objectMarking', value: [], operation: 'replace' }] },
      });
      // Administrators included, as on creation
      await queryAsAdminWithError({ query: DEPLOYMENT_MARKING_DELETE, variables: { id: deploymentId, toId: MARKING_TLP_AMBER } }, undefined, 'FORBIDDEN_ACCESS');
      const deployment = await internalLoadById(testContext, ADMIN_USER, deploymentId) as unknown as Record<string, string[] | undefined>;
      expect(deployment[RELATION_OBJECT_MARKING]).toEqual([amber.internal_id]);
    } finally {
      await unmarkIndicatorAndPair([deploymentId]);
    }
  });

  it('should accept the upsert of a marked deployment that does not repeat its markings, and keep them', async () => {
    const amber = await internalLoadById(testContext, ADMIN_USER, MARKING_TLP_AMBER) as unknown as { internal_id: string };
    await markPairAndIndicator([deploymentId], [amber.internal_id]);
    // Neither streamed nor kept: the raw stream counts of the suite are unchanged
    const streamed = vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never);
    try {
      const upserted = await queryAsAdminWithSuccess({
        query: RELATION_ADD,
        variables: { input: { fromId: indicatorId, toId: platformId, relationship_type: 'deployed-on', description: 'Deployment notes', update: true } },
      });
      expect(upserted.data?.stixCoreRelationshipAdd.id).toEqual(deploymentId);
      const deployment = await internalLoadById(testContext, ADMIN_USER, deploymentId) as unknown as Record<string, string[] | undefined>;
      expect(deployment[RELATION_OBJECT_MARKING]).toEqual([amber.internal_id]);
    } finally {
      streamed.mockRestore();
      await unmarkIndicatorAndPair([deploymentId]);
    }
  });

  it('should share a deployment again with the organizations of both its ends after a sharing change of one end', async () => {
    await setOrganizations(platformId, [platformOrganizationId]);
    await repairPairMarkings(testContext, ADMIN_USER, { indicatorIds: [], platformIds: [platformId] });
    expect(await loadOrganizations(deploymentId)).toEqual([platformOrganizationId]);
  });

  it('should be idempotent and never downgrade an active deployment', async () => {
    const same = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_DEPLOYMENT,
      variables: { indicatorId, platformId, status: 'deployed', externalId: 'ti-1' },
    });
    expect(same.data?.indicatorReportDeployment.id).toEqual(deploymentId);
    const active = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_DEPLOYMENT,
      variables: { indicatorId, platformId, status: 'active' },
    });
    expect(active.data?.indicatorReportDeployment.deployment_status).toEqual('active');
    const repush = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_DEPLOYMENT,
      variables: { indicatorId, platformId, status: 'deployed' },
    });
    expect(repush.data?.indicatorReportDeployment.deployment_status).toEqual('active');
  });

  it('should record a vendor failure', async () => {
    const failed = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_DEPLOYMENT,
      variables: { indicatorId, platformId, status: 'failed', metadata: { error_message: 'Indicator quota exceeded' } },
    });
    expect(failed.data?.indicatorReportDeployment.deployment_status).toEqual('failed');
    expect(failed.data?.indicatorReportDeployment.error_message).toEqual('Indicator quota exceeded');
  });

  it('should reject the platform reserved expired status and unauthorized users', async () => {
    const expired = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_DEPLOYMENTS,
      variables: { platformId, reports: [{ indicatorId, status: 'expired' }] },
    });
    expect(expired.data?.indicatorReportDeployments.processed).toEqual(0);
    expect(expired.data?.indicatorReportDeployments.errors.length).toEqual(1);
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
      query: REPORT_DEPLOYMENT,
      variables: { indicatorId, platformId, status: 'deployed' },
    });
  });

  it('should process batches and report per indicator errors', async () => {
    const result = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_DEPLOYMENTS,
      variables: {
        platformId,
        reports: [
          { indicatorId, status: 'active', externalId: 'ti-1' },
          { indicatorId: secondIndicatorId, status: 'deployed', externalId: 'ti-2' },
          { indicatorId: 'indicator--00000000-0000-4000-8000-000000000000', status: 'deployed' },
        ],
      },
    });
    const batch = result.data?.indicatorReportDeployments;
    expect(batch.processed).toEqual(2);
    expect(batch.created).toEqual(1);
    expect(batch.updated).toEqual(1);
    expect(batch.errors.length).toEqual(1);
    expect(batch.errors[0].indicatorId).toEqual('indicator--00000000-0000-4000-8000-000000000000');
  });

  it('should apply the reports of one indicator in a batch in the batch order, whatever ids name it', async () => {
    // Neither streamed nor kept: the raw stream counts of the suite are unchanged
    const streamed = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
    ];
    let orderedId: string | undefined;
    try {
      const created = await queryAsAdminWithSuccess({
        query: INDICATOR_ADD,
        variables: { input: { name: 'ordered.evil.example', pattern: "[domain-name:value = 'ordered.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
      });
      orderedId = created.data?.indicatorAdd.id as string;
      const result = await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: REPORT_DEPLOYMENTS,
        variables: {
          platformId,
          reports: [
            { indicatorId: orderedId, status: 'deployed', externalId: 'ordered-1' },
            { indicatorId: created.data?.indicatorAdd.standard_id, status: 'active', externalId: 'ordered-1' },
            { indicatorId: orderedId, status: 'removed', externalId: 'ordered-1' },
          ],
        },
      });
      expect(result.data?.indicatorReportDeployments).toMatchObject({ processed: 3, created: 1, updated: 2, errors: [] });
      const deployment = await findDeployedOn(testContext, ADMIN_USER, orderedId, platformId);
      expect(deployment?.deployment_status).toEqual('removed');
      expect(deployment?.removed_at).toBeTruthy();
    } finally {
      if (orderedId) {
        await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: orderedId } });
      }
      streamed.forEach((spy) => spy.mockRestore());
    }
  });

  it('should count hits on a stable sighting and ignore replays', async () => {
    const first = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_HITS,
      variables: { indicatorId, platformId, count: 3, firstHit: '2026-09-30T10:00:00.000Z', lastHit: '2026-10-01T10:00:00.000Z' },
    });
    const sighting = first.data?.indicatorReportHits;
    expect(sighting.attribute_count).toEqual(3);
    expect(sighting.x_opencti_negative).toEqual(false);
    const replay = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_HITS,
      variables: { indicatorId, platformId, count: 3, lastHit: '2026-10-01T10:00:00.000Z' },
    });
    expect(replay.data?.indicatorReportHits.id).toEqual(sighting.id);
    expect(replay.data?.indicatorReportHits.attribute_count).toEqual(3);
    const next = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_HITS,
      variables: { indicatorId, platformId, count: 2, lastHit: '2026-10-02T10:00:00.000Z' },
    });
    expect(next.data?.indicatorReportHits.id).toEqual(sighting.id);
    expect(next.data?.indicatorReportHits.attribute_count).toEqual(5);
    const list = await queryAsAdminWithSuccess({ query: DEPLOYMENTS_LIST, variables: { toId: [platformId] } });
    const deployment = list.data?.stixCoreRelationships.edges.map((e: { node: { id: string } }) => e.node).find((n: { id: string }) => n.id === deploymentId);
    expect(deployment.hit_count).toEqual(5);
    expect(new Date(deployment.last_hit_at).toISOString()).toEqual('2026-10-02T10:00:00.000Z');
  });

  it('should restore a lost hits sighting on replay without counting the hits twice', async () => {
    const current = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_HITS,
      variables: { indicatorId, platformId, count: 2, lastHit: '2026-10-02T10:00:00.000Z' },
    });
    // A deployment written without its sighting, as left by a failed second write
    await deleteElementById(testContext, ADMIN_USER, current.data?.indicatorReportHits.id, STIX_SIGHTING_RELATIONSHIP);
    const retried = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_HITS,
      variables: { indicatorId, platformId, count: 2, lastHit: '2026-10-02T10:00:00.000Z' },
    });
    expect(retried.data?.indicatorReportHits.attribute_count).toEqual(5);
    // The first hit of the first report, kept on the deployment, not the first hit of the retry
    expect(new Date(retried.data?.indicatorReportHits.first_seen).toISOString()).toEqual('2026-09-30T10:00:00.000Z');
    expect(new Date(retried.data?.indicatorReportHits.last_seen).toISOString()).toEqual('2026-10-02T10:00:00.000Z');
    const list = await queryAsAdminWithSuccess({ query: DEPLOYMENTS_LIST, variables: { toId: [platformId] } });
    const deployment = list.data?.stixCoreRelationships.edges.map((e: { node: { id: string } }) => e.node).find((n: { id: string }) => n.id === deploymentId);
    expect(deployment.hit_count).toEqual(5);
    expect(new Date(deployment.first_hit_at).toISOString()).toEqual('2026-09-30T10:00:00.000Z');
  });

  it('should repair on replay a hits sighting whose update failed after the deployment was written', async () => {
    const current = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_HITS,
      variables: { indicatorId, platformId, count: 2, lastHit: '2026-10-02T10:00:00.000Z' },
    });
    const sightingId = current.data?.indicatorReportHits.id;
    const stored = await internalLoadById(testContext, ADMIN_USER, sightingId) as unknown as { _index: string };
    // The sighting as it was before the last counted report: 2 hits and its last hit missing
    const staleScript = "ctx._source.attribute_count = 3; ctx._source.last_seen = '2026-10-01T10:00:00.000Z';";
    await elUpdate(testContext, stored._index, sightingId, { script: { source: staleScript, lang: 'painless' } });
    const retried = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_HITS,
      variables: { indicatorId, platformId, count: 2, lastHit: '2026-10-02T10:00:00.000Z' },
    });
    expect(retried.data?.indicatorReportHits.id).toEqual(sightingId);
    expect(retried.data?.indicatorReportHits.attribute_count).toEqual(5);
    expect(new Date(retried.data?.indicatorReportHits.last_seen).toISOString()).toEqual('2026-10-02T10:00:00.000Z');
  });

  it('should refuse an edit removing from the hits sighting a marking of its indicator', async () => {
    const amber = await internalLoadById(testContext, ADMIN_USER, MARKING_TLP_AMBER) as unknown as { internal_id: string };
    const sightingStixId = hitsSightingStixId(indicatorId, platformId);
    const sighting = await internalLoadById(testContext, ADMIN_USER, sightingStixId, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as { internal_id: string };
    // Side-channel only, so the raw stream counts of the suite are unchanged; the editor reads the pair meanwhile
    await markPairAndIndicator([sighting.internal_id, deploymentId], [amber.internal_id]);
    await lendPairToEditor(sighting.internal_id);
    try {
      await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: SIGHTING_MARKING_DELETE, variables: { id: sighting.internal_id, toId: MARKING_TLP_AMBER } });
      await queryAsAdminWithError({ query: SIGHTING_MARKING_DELETE, variables: { id: sighting.internal_id, toId: MARKING_TLP_AMBER } }, undefined, 'FORBIDDEN_ACCESS');
      const stored = await internalLoadById(testContext, ADMIN_USER, sighting.internal_id, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as Record<string, string[] | undefined>;
      expect(stored[RELATION_OBJECT_MARKING]).toEqual([amber.internal_id]);
    } finally {
      await setOrganizations(sighting.internal_id, [platformOrganizationId]);
      await setOrganizations(platformId, [platformOrganizationId]);
      await unmarkIndicatorAndPair([sighting.internal_id, deploymentId]);
      await sharePairFromItsEnds();
    }
  });

  it('should leave what the hits sighting records to the accounts reporting hits', async () => {
    const sightingStixId = hitsSightingStixId(indicatorId, platformId);
    const before = await internalLoadById(testContext, ADMIN_USER, sightingStixId, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as {
      internal_id: string;
      attribute_count: number;
      description: string;
    };
    // Only the hits report writes it: not even the reporting connector account through the generic edition
    await queryAsUserIsExpectedForbidden(USER_CONNECTOR, {
      query: SIGHTING_FIELD_PATCH,
      variables: { id: before.internal_id, input: [{ key: 'description', value: ['edited outside the report'] }] },
    });
    // Nor does it lose the identifier the report finds it by: that identifier is its standard id
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: SIGHTING_FIELD_PATCH,
      variables: { id: before.internal_id, input: [{ key: 'x_opencti_stix_ids', value: [], operation: 'replace' }] },
    });
    const byReservedId = await internalLoadById(testContext, ADMIN_USER, sightingStixId, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as { internal_id: string };
    expect(byReservedId.internal_id).toEqual(before.internal_id);
    // Side-channel only, so the raw stream counts of the suite are unchanged; the editor reads the pair meanwhile
    await lendPairToEditor(before.internal_id);
    try {
      await queryAsUserIsExpectedForbidden(USER_EDITOR, {
        query: SIGHTING_FIELD_PATCH,
        variables: { id: before.internal_id, input: [{ key: 'attribute_count', value: ['1'] }] },
      });
      await queryAsUserIsExpectedForbidden(USER_EDITOR, {
        query: SIGHTING_FIELD_PATCH,
        variables: { id: before.internal_id, input: [{ key: 'x_opencti_negative', value: ['true'] }] },
      });
      const after = await internalLoadById(testContext, ADMIN_USER, before.internal_id, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as { attribute_count: number };
      expect(after.attribute_count).toEqual(before.attribute_count);
    } finally {
      await setOrganizations(before.internal_id, [platformOrganizationId]);
      await setOrganizations(platformId, [platformOrganizationId]);
      await sharePairFromItsEnds();
    }
  });

  it('should leave the write-back mutations to connector accounts', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: REPORT_DEPLOYMENT,
      variables: { indicatorId, platformId, status: 'active' },
    });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: REPORT_DEPLOYMENTS,
      variables: { platformId, reports: [{ indicatorId, status: 'active' }] },
    });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: REPORT_HITS,
      variables: { indicatorId, platformId, count: 50, lastHit: '2026-10-03T10:00:00.000Z' },
    });
  });

  it('should refuse a hits report without the time of its last hit, which keeps a retried report from being counted twice', async () => {
    await queryAsUserIsExpectedError(
      USER_CONNECTOR,
      { query: REPORT_HITS, variables: { indicatorId, platformId, count: 1 } },
      'The time of the last hit is required: it keeps a retried report from being counted twice',
    );
  });

  it('should refuse a hits report whose last hit is ahead of the platform clock, which would hide the reports before it', async () => {
    const lastHit = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    await queryAsUserIsExpectedError(
      USER_CONNECTOR,
      { query: REPORT_HITS, variables: { indicatorId, platformId, count: 1, lastHit } },
      'The time of the last hit cannot be more than 5 minutes ahead of the platform clock',
    );
  });

  it('should keep the report id of the hits report that created the deployment, so its retry is not counted twice', async () => {
    // Neither streamed nor kept: the raw stream counts of the suite are unchanged
    const streamed = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
    ];
    let hitIndicatorId: string | undefined;
    try {
      const created = await queryAsAdminWithSuccess({
        query: INDICATOR_ADD,
        variables: { input: { name: 'first-hit.evil.example', pattern: "[domain-name:value = 'first-hit.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
      });
      hitIndicatorId = created.data?.indicatorAdd.id as string;
      await setOrganizations(hitIndicatorId, [testOrganizationId, platformOrganizationId]);
      // No deployment yet: the first hits report creates it
      const report = { indicatorId: hitIndicatorId, platformId, count: 2, lastHit: '2026-10-03T10:00:00.000Z', reportId: 'hits-report-1' };
      const first = await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_HITS, variables: report });
      expect(first.data?.indicatorReportHits.attribute_count).toEqual(2);
      const retried = await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_HITS, variables: report });
      expect(retried.data?.indicatorReportHits.attribute_count).toEqual(2);
      // Another report ending at the same instant is counted
      const other = await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_HITS, variables: { ...report, count: 1, reportId: 'hits-report-2' } });
      expect(other.data?.indicatorReportHits.attribute_count).toEqual(3);
      // The reports counted at the last hit are read back, so a client reconciling its imports sees them
      const read = await queryAsAdminWithSuccess({ query: DEPLOYMENT_HITS_READ, variables: { fromId: [hitIndicatorId], toId: [platformId] } });
      const deployment = read.data?.stixCoreRelationships.edges[0].node;
      expect(new Date(deployment.last_hit_at).toISOString()).toEqual('2026-10-03T10:00:00.000Z');
      expect(deployment.last_hit_report_ids).toEqual(['hits-report-1', 'hits-report-2']);
    } finally {
      if (hitIndicatorId) {
        await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: hitIndicatorId } });
      }
      streamed.forEach((spy) => spy.mockRestore());
    }
  });

  it('should share a hits sighting created by the generic path with the organizations of its pair only', async () => {
    // Neither streamed nor kept: the raw stream counts of the suite are unchanged
    const streamed = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
    ];
    let sharedIndicatorId: string | undefined;
    try {
      const created = await queryAsAdminWithSuccess({
        query: INDICATOR_ADD,
        variables: { input: { name: 'shared-pair.evil.example', pattern: "[domain-name:value = 'shared-pair.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
      });
      sharedIndicatorId = created.data?.indicatorAdd.id as string;
      await setOrganizations(sharedIndicatorId, [testOrganizationId, platformOrganizationId]);
      const sighting = await createRelation(testContext, ADMIN_USER, {
        fromId: sharedIndicatorId,
        toId: platformId,
        relationship_type: STIX_SIGHTING_RELATIONSHIP,
        stix_id: hitsSightingStixId(sharedIndicatorId, platformId),
        objectOrganization: [testOrganizationId],
        attribute_count: 1,
        x_opencti_negative: false,
      }) as unknown as { internal_id: string };
      const stored = await internalLoadById(testContext, ADMIN_USER, sighting.internal_id, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as Record<string, string[] | undefined>;
      // The platform is shared with the platform organization only: so is the sighting, whatever the input says
      expect(stored[RELATION_GRANTED_TO]).toEqual([platformOrganizationId]);
      // Nor does an upsert of the sighting widen it
      await createRelation(testContext, ADMIN_USER, {
        fromId: sharedIndicatorId,
        toId: platformId,
        relationship_type: STIX_SIGHTING_RELATIONSHIP,
        stix_id: hitsSightingStixId(sharedIndicatorId, platformId),
        objectOrganization: [testOrganizationId],
        attribute_count: 1,
        x_opencti_negative: false,
        update: true,
      });
      const upserted = await internalLoadById(testContext, ADMIN_USER, sighting.internal_id, { type: STIX_SIGHTING_RELATIONSHIP });
      expect((upserted as unknown as Record<string, string[] | undefined>)[RELATION_GRANTED_TO]).toEqual([platformOrganizationId]);
    } finally {
      if (sharedIndicatorId) {
        await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: sharedIndicatorId } });
      }
      streamed.forEach((spy) => spy.mockRestore());
    }
  });

  it('should never count hits on a sighting holding the hits sighting id that is not the positive sighting of the pair', async () => {
    // Neither streamed nor kept: the raw stream counts of the suite are unchanged
    const streamed = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
    ];
    let heldIndicatorId: string | undefined;
    try {
      const created = await queryAsAdminWithSuccess({
        query: INDICATOR_ADD,
        variables: { input: { name: 'held-id.evil.example', pattern: "[domain-name:value = 'held-id.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
      });
      heldIndicatorId = created.data?.indicatorAdd.id as string;
      await setOrganizations(heldIndicatorId, [testOrganizationId, platformOrganizationId]);
      // A negative sighting created beforehand under the deterministic id of the hits sighting (administrators can)
      const held = await createRelation(testContext, ADMIN_USER, {
        fromId: heldIndicatorId,
        toId: platformId,
        relationship_type: STIX_SIGHTING_RELATIONSHIP,
        stix_id: hitsSightingStixId(heldIndicatorId, platformId),
        attribute_count: 1,
        x_opencti_negative: true,
      }) as unknown as { internal_id: string };
      await queryAsUserIsExpectedError(
        USER_CONNECTOR,
        { query: REPORT_HITS, variables: { indicatorId: heldIndicatorId, platformId, count: 4, lastHit: '2026-10-03T10:00:00.000Z' } },
        'The hits sighting identifier of this indicator and security platform is held by another sighting',
      );
      const after = await internalLoadById(testContext, ADMIN_USER, held.internal_id, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as { attribute_count: number };
      expect(after.attribute_count).toEqual(1);
    } finally {
      if (heldIndicatorId) {
        await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: heldIndicatorId } });
      }
      streamed.forEach((spy) => spy.mockRestore());
    }
  });

  it('should keep the hits sighting of a pair apart from the ordinary sightings sharing its time window', async () => {
    // Neither streamed nor kept: the raw stream counts of the suite are unchanged
    const streamed = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
    ];
    let windowIndicatorId: string | undefined;
    try {
      const created = await queryAsAdminWithSuccess({
        query: INDICATOR_ADD,
        variables: { input: { name: 'same-window.evil.example', pattern: "[domain-name:value = 'same-window.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
      });
      windowIndicatorId = created.data?.indicatorAdd.id as string;
      await setOrganizations(windowIndicatorId, [testOrganizationId, platformOrganizationId]);
      const lastHit = '2026-10-03T10:00:00.000Z';
      const ordinaryInput = {
        fromId: windowIndicatorId,
        toId: platformId,
        relationship_type: STIX_SIGHTING_RELATIONSHIP,
        first_seen: lastHit,
        last_seen: lastHit,
        x_opencti_negative: false,
      };
      // An ordinary sighting of the pair, seen at the time of the hits
      const ordinary = await createRelation(testContext, ADMIN_USER, { ...ordinaryInput, attribute_count: 7 }) as unknown as { internal_id: string };
      // Nor does an edit give it the identifier of the hits sighting, administrators included: it keeps its own access
      const hitsStixId = hitsSightingStixId(windowIndicatorId, platformId);
      await queryAsAdminWithError(
        { query: SIGHTING_FIELD_PATCH, variables: { id: ordinary.internal_id, input: [{ key: 'x_opencti_stix_ids', value: [hitsStixId], operation: 'add' }] } },
        'A sighting gets the identifier of a hits or validation result sighting at its creation only',
      );
      // The hits report creates the hits sighting of the pair, it never takes the ordinary one over
      const reported = await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: REPORT_HITS,
        variables: { indicatorId: windowIndicatorId, platformId, count: 2, lastHit },
      });
      expect(reported.data?.indicatorReportHits.attribute_count).toEqual(2);
      const hits = await internalLoadById(testContext, ADMIN_USER, hitsStixId, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as { internal_id: string };
      expect(hits.internal_id).not.toEqual(ordinary.internal_id);
      const untouched = await internalLoadById(testContext, ADMIN_USER, ordinary.internal_id, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as {
        attribute_count: number;
        x_opencti_stix_ids?: string[];
      };
      expect(untouched.attribute_count).toEqual(7);
      expect(untouched.x_opencti_stix_ids ?? []).not.toContain(hitsStixId);
      // Nor does a later ordinary sighting of the same window merge into the hits sighting
      const later = await createRelation(testContext, ADMIN_USER, { ...ordinaryInput, attribute_count: 3 }) as unknown as { internal_id: string };
      expect(later.internal_id).not.toEqual(hits.internal_id);
      const kept = await internalLoadById(testContext, ADMIN_USER, hits.internal_id, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as { attribute_count: number };
      expect(kept.attribute_count).toEqual(2);
    } finally {
      if (windowIndicatorId) {
        await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: windowIndicatorId } });
      }
      streamed.forEach((spy) => spy.mockRestore());
    }
  });

  it('should apply the edition rules of the hits sighting to an upsert reaching it through another of its ids', async () => {
    const hitsStixId = hitsSightingStixId(indicatorId, platformId);
    const before = await internalLoadById(testContext, ADMIN_USER, hitsStixId, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as {
      internal_id: string;
      standard_id: string;
      x_opencti_stix_ids?: string[];
      attribute_count: number;
    };
    // The reserved id is its standard id; it is given another id here (side channel, no event), which the creation does
    // not check, to reach it by an upsert
    expect(before.standard_id).toEqual(hitsStixId);
    const otherId = 'sighting--2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6f';
    const setStixIds = async (ids: string[]) => {
      const stored = await internalLoadById(testContext, ADMIN_USER, before.internal_id) as unknown as { _index: string };
      const script = { source: "ctx._source['x_opencti_stix_ids'] = params.ids", lang: 'painless', params: { ids } };
      await elUpdate(testContext, stored._index, before.internal_id, { script });
    };
    await setStixIds([...(before.x_opencti_stix_ids ?? []), otherId]);
    const platformOrganizations = await loadOrganizations(platformId);
    const sightingOrganizations = await loadOrganizations(before.internal_id, STIX_SIGHTING_RELATIONSHIP);
    // Side-channel only, so the raw stream counts of the suite are unchanged; the editor reads the pair meanwhile
    await lendPairToEditor(before.internal_id);
    try {
      await queryAsUserIsExpectedForbidden(USER_EDITOR, {
        query: SIGHTING_ADD,
        variables: {
          input: { fromId: indicatorId, toId: platformId, stix_id: otherId, attribute_count: before.attribute_count + 10, x_opencti_negative: false, update: true },
        },
      });
      const after = await internalLoadById(testContext, ADMIN_USER, before.internal_id, { type: STIX_SIGHTING_RELATIONSHIP }) as unknown as { attribute_count: number };
      expect(after.attribute_count).toEqual(before.attribute_count);
    } finally {
      await setOrganizations(before.internal_id, sightingOrganizations);
      await setOrganizations(platformId, platformOrganizations);
      await setStixIds(before.x_opencti_stix_ids ?? []);
      await sharePairFromItsEnds();
    }
  });

  it('should refuse a negative hit count on the generic edit and upsert paths, as the next hit report adds to it', async () => {
    await queryAsUserIsExpectedError(
      USER_CONNECTOR,
      { query: DEPLOYMENT_FIELD_PATCH, variables: { id: deploymentId, input: [{ key: 'hit_count', value: ['-2'], operation: 'replace' }] } },
      'The counter should be a non-negative integer',
    );
    await queryAsUserIsExpectedError(
      USER_CONNECTOR,
      { query: RELATION_ADD, variables: { input: { fromId: indicatorId, toId: platformId, relationship_type: 'deployed-on', hit_count: -2, update: true } } },
      'The counter should be a non-negative integer',
    );
    const list = await queryAsAdminWithSuccess({ query: DEPLOYMENTS_LIST, variables: { toId: [platformId] } });
    const deployment = list.data?.stixCoreRelationships.edges.map((e: { node: { id: string } }) => e.node).find((n: { id: string }) => n.id === deploymentId);
    expect(deployment.hit_count).toEqual(5);
  });

  it('should refuse a status outside the statuses of its field on the generic edit path, administrators included', async () => {
    await queryAsUserIsExpectedError(
      USER_CONNECTOR,
      { query: DEPLOYMENT_FIELD_PATCH, variables: { id: deploymentId, input: [{ key: 'deployment_status', value: ['invalid-status'], operation: 'replace' }] } },
      'Status is not one of the statuses of the field',
    );
    await queryAsAdminWithError(
      { query: DEPLOYMENT_FIELD_PATCH, variables: { id: deploymentId, input: [{ key: 'validation_status', value: ['invalid-status'], operation: 'replace' }] } },
      'Status is not one of the statuses of the field',
    );
    const list = await queryAsAdminWithSuccess({ query: DEPLOYMENTS_LIST, variables: { toId: [platformId] } });
    const deployment = list.data?.stixCoreRelationships.edges.map((e: { node: { id: string } }) => e.node).find((n: { id: string }) => n.id === deploymentId);
    expect(deployment.deployment_status).not.toEqual('invalid-status');
    expect(deployment.validation_status).not.toEqual('invalid-status');
  });

  it('should apply the edition rules of a deployment to the operations of an upsert, administrators included', async () => {
    const upsertWith = (operation: { key: string; value: string[] }) => ({
      query: RELATION_ADD,
      variables: { input: { fromId: indicatorId, toId: platformId, relationship_type: 'deployed-on', update: true, upsertOperations: [{ ...operation, operation: 'replace' }] } },
    });
    const before = await internalLoadById(testContext, ADMIN_USER, deploymentId) as unknown as Record<string, unknown>;
    // Upsert operations are reserved to administrators
    await queryAsUserIsExpectedError(USER_EDITOR, upsertWith({ key: 'deployment_status', value: ['pending'] }), 'User has insufficient rights to use upsertOperations');
    // whose operations are checked like any edit of the deployment
    await queryAsAdminWithError(upsertWith({ key: 'validation_status', value: ['invalid-status'] }), 'Status is not one of the statuses of the field');
    await queryAsAdminWithError(upsertWith({ key: 'deployment_status', value: ['invalid-status'] }), 'Status is not one of the statuses of the field');
    const after = await internalLoadById(testContext, ADMIN_USER, deploymentId) as unknown as Record<string, unknown>;
    ['deployment_status', 'validation_status'].forEach((field) => expect(after[field]).toEqual(before[field]));
  });

  it('should add the reporting connector to the creators and the reporters of a deployment someone else created, heartbeats included', async () => {
    const connectorUserId = await getUserIdByEmail(USER_CONNECTOR.email);
    // Neither streamed nor kept: the raw stream counts of the suite are unchanged
    const streamed = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
    ];
    let reportedIndicatorId: string | undefined;
    try {
      const created = await queryAsAdminWithSuccess({
        query: INDICATOR_ADD,
        variables: { input: { name: 'reporters.evil.example', pattern: "[domain-name:value = 'reporters.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
      });
      reportedIndicatorId = created.data?.indicatorAdd.id as string;
      // Shared like the indicator of the other tests, so the connector account reads the deployment the same way
      await setOrganizations(reportedIndicatorId, [testOrganizationId, platformOrganizationId]);
      const imported = await queryAsAdminWithSuccess({
        query: RELATION_ADD,
        variables: { input: { fromId: reportedIndicatorId, toId: platformId, relationship_type: 'deployed-on', deployment_status: 'deployed' } },
      });
      const importedId = imported.data?.stixCoreRelationshipAdd.id;
      type Recorded = { creator_id: string[]; deployment_reporter_ids?: string[] };
      const recordedOf = async () => await internalLoadById(testContext, ADMIN_USER, importedId) as unknown as Recorded;
      const beforeReport = await recordedOf();
      expect(beforeReport.creator_id).not.toContain(connectorUserId);
      // Created through the generic path: its creator reported nothing, so it is no reporter
      expect(beforeReport.deployment_reporter_ids ?? []).toEqual([]);
      // A report whose write fails records nothing: the account does not speak for a report that was not written
      const failedWrite = vi.spyOn(middleware, 'patchAttribute').mockRejectedValueOnce(new Error('Write conflict'));
      try {
        await queryAsUserIsExpectedError(USER_CONNECTOR, { query: REPORT_DEPLOYMENT, variables: { indicatorId: reportedIndicatorId, platformId, status: 'deployed' } });
      } finally {
        failedWrite.mockRestore();
      }
      const afterFailedWrite = await recordedOf();
      expect(afterFailedWrite.creator_id).not.toContain(connectorUserId);
      expect(afterFailedWrite.deployment_reporter_ids ?? []).toEqual([]);
      // A heartbeat (same status) is accepted: the connector becomes a creator and a reporter once, the lifecycle is unchanged
      const heartbeat = await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_DEPLOYMENT, variables: { indicatorId: reportedIndicatorId, platformId, status: 'deployed' } });
      expect(heartbeat.data?.indicatorReportDeployment.deployment_status).toEqual('deployed');
      const afterHeartbeat = await recordedOf();
      expect(afterHeartbeat.creator_id).toContain(connectorUserId);
      expect(afterHeartbeat.creator_id).toContain(ADMIN_USER.id);
      expect(afterHeartbeat.deployment_reporter_ids).toEqual([connectorUserId]);
      // A later report keeps every creator and every reporter, without duplicates
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_DEPLOYMENT, variables: { indicatorId: reportedIndicatorId, platformId, status: 'active' } });
      const afterReport = await recordedOf();
      expect(afterReport.creator_id.filter((id) => id === connectorUserId)).toHaveLength(1);
      expect(afterReport.creator_id).toContain(ADMIN_USER.id);
      expect(afterReport.deployment_reporter_ids).toEqual([connectorUserId]);
    } finally {
      if (reportedIndicatorId) {
        await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: reportedIndicatorId } });
      }
      streamed.forEach((spy) => spy.mockRestore());
    }
  });

  it('should publish the first report of a deployment its connector created, so it counts as disseminated, then heartbeat', async () => {
    // Neither streamed nor kept: the raw stream counts of the suite are unchanged
    const streamed = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
    ];
    const updates = streamed[2];
    let reportedIndicatorId: string | undefined;
    try {
      const created = await queryAsAdminWithSuccess({
        query: INDICATOR_ADD,
        variables: { input: { name: 'first-report.evil.example', pattern: "[domain-name:value = 'first-report.evil.example']", pattern_type: 'stix', x_opencti_main_observable_type: 'Domain-Name' } },
      });
      reportedIndicatorId = created.data?.indicatorAdd.id as string;
      await setOrganizations(reportedIndicatorId, [testOrganizationId, platformOrganizationId]);
      // Created by the connector through the generic path: already a creator, never synchronized
      const pending = await queryAsUserWithSuccess(USER_CONNECTOR, {
        query: RELATION_ADD,
        variables: { input: { fromId: reportedIndicatorId, toId: platformId, relationship_type: 'deployed-on', deployment_status: 'pending' } },
      });
      expect(pending.data?.stixCoreRelationshipAdd.last_sync_at).toBeNull();
      // Same status, first report: published, so the counters of the indicator are refreshed
      const beforeFirst = updates.mock.calls.length;
      const first = await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_DEPLOYMENT, variables: { indicatorId: reportedIndicatorId, platformId, status: 'pending' } });
      expect(first.data?.indicatorReportDeployment.last_sync_at).not.toBeNull();
      expect(updates.mock.calls.length).toBeGreaterThan(beforeFirst);
      // Same status again: a heartbeat, never published
      const beforeHeartbeat = updates.mock.calls.length;
      await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_DEPLOYMENT, variables: { indicatorId: reportedIndicatorId, platformId, status: 'pending' } });
      expect(updates.mock.calls.length).toEqual(beforeHeartbeat);
    } finally {
      if (reportedIndicatorId) {
        await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: reportedIndicatorId } });
      }
      streamed.forEach((spy) => spy.mockRestore());
    }
  });

  it('should refuse deployment state written by a regular editor through the generic relationship creation', async () => {
    // Fabricated write-back evidence on a new deployment
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: RELATION_ADD,
      variables: { input: { fromId: secondIndicatorId, toId: platformId, relationship_type: 'deployed-on', deployment_status: 'active', hit_count: 40 } },
    });
    // Reset of the existing deployment through an upsert
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: RELATION_ADD,
      variables: { input: { fromId: indicatorId, toId: platformId, relationship_type: 'deployed-on', deployment_status: 'pending', hit_count: 0, update: true } },
    });
    const list = await queryAsAdminWithSuccess({ query: DEPLOYMENTS_LIST, variables: { toId: [platformId] } });
    const deployment = list.data?.stixCoreRelationships.edges.map((e: { node: { id: string } }) => e.node).find((n: { id: string }) => n.id === deploymentId);
    expect(deployment.deployment_status).toEqual('active');
    expect(deployment.hit_count).toEqual(5);
  });

  it('should refresh the derived indicator counters', async () => {
    await refreshIndicatorDeploymentCounters(testContext, [indicatorId, secondIndicatorId]);
    const indicator = await queryAsAdminWithSuccess({ query: INDICATOR_READ, variables: { id: indicatorId } });
    expect(indicator.data?.indicator.deployment_platforms_count).toEqual(1);
    expect(indicator.data?.indicator.deployment_failed_count).toEqual(0);
    expect(indicator.data?.indicator.hit_platforms_count).toEqual(1);
    expect(indicator.data?.indicator.validated_platforms_count).toEqual(0);
  });

  it('should stream a revoked indicator found live, as when revoked right after its first deployment', async () => {
    const stored = await internalLoadById(testContext, ADMIN_USER, indicatorId) as unknown as { _index: string };
    const setSource = (source: string) => elUpdate(testContext, stored._index, indicatorId, { script: { source, lang: 'painless' } });
    // The revocation was stored and streamed while the counter still read zero
    await setSource('ctx._source.revoked = true; ctx._source.deployment_platforms_count = 0');
    const streamed = vi.spyOn(streamHandler, 'storeUpdateEvent');
    try {
      await refreshIndicatorDeploymentCounters(testContext, [indicatorId]);
      expect(streamed).toHaveBeenCalledTimes(1);
      type StreamedCall = [unknown, unknown, Record<string, unknown>, Record<string, unknown>, unknown, { noHistory?: boolean }];
      const [, , previous, current, , opts] = streamed.mock.calls[0] as unknown as StreamedCall;
      expect(current.internal_id).toEqual(indicatorId);
      expect(current.revoked).toEqual(true);
      expect(previous.deployment_platforms_count).toEqual(0);
      expect(current.deployment_platforms_count).toEqual(1);
      expect(opts.noHistory).toEqual(true);
      // Streamed live once: the next refreshes, and an indicator event already showing it live, stream nothing more
      await refreshIndicatorDeploymentCounters(testContext, [indicatorId]);
      await refreshIndicatorDeploymentCounters(testContext, [indicatorId], new Map([[indicatorId, true]]));
      expect(streamed).toHaveBeenCalledTimes(1);
    } finally {
      streamed.mockRestore();
      await setSource('ctx._source.revoked = false');
    }
  });

  it('should export the lifecycle in the STIX extension', async () => {
    const stix = await stixLoadById(testContext, ADMIN_USER, deploymentId) as unknown as { extensions: Record<string, Record<string, unknown>> };
    const extension = stix.extensions['extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba'];
    expect(extension.deployment_status).toEqual('active');
    expect(extension.hit_count).toEqual(5);
    expect(extension.external_id).toEqual('ti-1');
  });

  it('should support analyst retry and withdrawal', async () => {
    const removed = await queryAsUserWithSuccess(USER_CONNECTOR, { query: DEPLOYMENT_REMOVE, variables: { id: deploymentId } });
    expect(removed.data?.indicatorDeploymentRemove.revoked).toEqual(true);
    // The withdrawal starts the removal grace period
    expect((await findDeployedOn(testContext, ADMIN_USER, indicatorId, platformId))?.removal_requested_at).toBeTruthy();
    // Still active on the platform: nothing to retry
    await queryAsAdminWithError(
      { query: DEPLOYMENT_RETRY, variables: { id: deploymentId } },
      'Only a failed, removed or expired deployment can be retried',
    );
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: REPORT_DEPLOYMENT,
      variables: { indicatorId, platformId, status: 'failed', metadata: { error_message: 'Indicator quota exceeded' } },
    });
    // An analyst action: no connector capability needed
    const retried = await queryAsUserWithSuccess(USER_EDITOR, { query: DEPLOYMENT_RETRY, variables: { id: deploymentId } });
    expect(retried.data?.indicatorDeploymentRetry.revoked).toEqual(false);
    expect(retried.data?.indicatorDeploymentRetry.deployment_status).toEqual('pending');
    expect(retried.data?.indicatorDeploymentRetry.error_message).toBeNull();
    // Deployed again: the removal is no longer requested
    expect((await findDeployedOn(testContext, ADMIN_USER, indicatorId, platformId))?.removal_requested_at).toBeFalsy();
  });

  it('should flag withdrawn deployments without removal confirmation as expired', async () => {
    await queryAsUserWithSuccess(USER_CONNECTOR, { query: REPORT_DEPLOYMENT, variables: { indicatorId, platformId, status: 'active' } });
    await queryAsUserWithSuccess(USER_CONNECTOR, { query: DEPLOYMENT_REMOVE, variables: { id: deploymentId } });
    // Grace period of 0 ms: the withdrawal is already older than the threshold
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    const flagged = await flagExpiredDeployments(testContext, ADMIN_USER, 0, 100);
    expect(flagged).toBeGreaterThanOrEqual(1);
    const list = await queryAsAdminWithSuccess({
      query: DEPLOYMENTS_LIST,
      variables: { toId: [platformId], filters: { mode: 'and', filters: [{ key: 'deployment_status', values: ['expired'] }], filterGroups: [] } },
    });
    const ids = list.data?.stixCoreRelationships.edges.map((e: { node: { id: string } }) => e.node.id);
    expect(ids).toContain(deploymentId);
  });

  it('should compute the dissemination assurance metrics', async () => {
    const global = await queryAsAdminWithSuccess({ query: METRICS, variables: {} });
    const metrics = global.data?.disseminationAssuranceMetrics;
    expect(metrics.funnel.created).toBeGreaterThanOrEqual(2);
    expect(metrics.funnel.disseminated).toBeGreaterThanOrEqual(1);
    const perPlatform = await queryAsAdminWithSuccess({ query: METRICS, variables: { platformId } });
    const platformMetrics = perPlatform.data?.disseminationAssuranceMetrics;
    expect(platformMetrics.funnel.disseminated).toEqual(2);
    expect(platformMetrics.funnel.expired_still_deployed).toEqual(1);
    expect(platformMetrics.funnel.hit).toEqual(1);
    const statuses = Object.fromEntries(platformMetrics.deployment_statuses.map((s: { status: string; count: number }) => [s.status, s.count]));
    expect(statuses.expired).toEqual(1);
    expect(statuses.deployed).toEqual(1);
    expect(platformMetrics.deployments_by_platform[0].platform.id).toEqual(platformId);
    expect(platformMetrics.proven_share).toEqual(0);
  });

  it('should keep a deployment flagged expired in the expired still deployed views', async () => {
    const indicator = await queryAsAdminWithSuccess({ query: INDICATOR_READ, variables: { id: indicatorId } });
    expect(indicator.data?.indicator.deployment_platforms_count).toEqual(0);
    expect(indicator.data?.indicator.deployment_expired_count).toEqual(1);
    expect(indicator.data?.indicator.deployments_count).toEqual(1);
    const global = await queryAsAdminWithSuccess({ query: METRICS, variables: {} });
    expect(global.data?.disseminationAssuranceMetrics.funnel.expired_still_deployed).toBeGreaterThanOrEqual(1);
    expect(global.data?.disseminationAssuranceMetrics.funnel.disseminated).toBeGreaterThanOrEqual(2);
  });

  // Side-channel writes below: no stream event, so the raw stream counts of the suite are unchanged.
  const setCounterScript = (source: string) => ({ script: { source, lang: 'painless' } });

  it('should count on a platform the live deployments of a revoked indicator before they are flagged expired', async () => {
    const before = await queryAsAdminWithSuccess({ query: METRICS, variables: { platformId } });
    const flaggedOnly = before.data?.disseminationAssuranceMetrics.funnel.expired_still_deployed;
    const stored = await internalLoadById(testContext, ADMIN_USER, secondIndicatorId) as unknown as { _index: string };
    await elUpdate(testContext, stored._index, secondIndicatorId, setCounterScript('ctx._source.revoked = true'));
    try {
      const revoked = await queryAsAdminWithSuccess({ query: METRICS, variables: { platformId } });
      expect(revoked.data?.disseminationAssuranceMetrics.funnel.expired_still_deployed).toEqual(flaggedOnly + 1);
      const global = await queryAsAdminWithSuccess({ query: METRICS, variables: {} });
      expect(global.data?.disseminationAssuranceMetrics.funnel.expired_still_deployed).toBeGreaterThanOrEqual(2);
      // More expired indicators than live deployments on the platform: the count scans the live deployments instead
      const first = await internalLoadById(testContext, ADMIN_USER, indicatorId) as unknown as { _index: string };
      await elUpdate(testContext, first._index, indicatorId, setCounterScript('ctx._source.revoked = true'));
      try {
        const bothRevoked = await queryAsAdminWithSuccess({ query: METRICS, variables: { platformId } });
        expect(bothRevoked.data?.disseminationAssuranceMetrics.funnel.expired_still_deployed).toEqual(flaggedOnly + 1);
      } finally {
        await elUpdate(testContext, first._index, indicatorId, setCounterScript('ctx._source.revoked = false'));
      }
    } finally {
      await elUpdate(testContext, stored._index, secondIndicatorId, setCounterScript('ctx._source.revoked = false'));
    }
  });

  it('should backfill a counter added after the indicator got its counters, by recomputation', async () => {
    const stored = await internalLoadById(testContext, ADMIN_USER, indicatorId) as unknown as { _index: string };
    await elUpdate(testContext, stored._index, indicatorId, setCounterScript("ctx._source.remove('deployments_count')"));
    const backfilled = await backfillIndicatorDeploymentCounters(testContext, 100);
    expect(backfilled).toBeGreaterThanOrEqual(1);
    const indicator = await queryAsAdminWithSuccess({ query: INDICATOR_READ, variables: { id: indicatorId } });
    expect(indicator.data?.indicator.deployments_count).toEqual(1);
  });

  it('should backfill a deployed indicator without any counter from its deployments, never with zeros', async () => {
    const stored = await internalLoadById(testContext, ADMIN_USER, indicatorId) as unknown as { _index: string };
    const removeAll = COUNTER_FIELDS.map((field) => `ctx._source.remove('${field}');`).join(' ');
    await elUpdate(testContext, stored._index, indicatorId, setCounterScript(removeAll));
    const backfilled = await backfillIndicatorDeploymentCounters(testContext, 1000);
    expect(backfilled).toBeGreaterThanOrEqual(1);
    const indicator = await queryAsAdminWithSuccess({ query: INDICATOR_READ, variables: { id: indicatorId } });
    expect(indicator.data?.indicator.deployments_count).toEqual(1);
    expect(indicator.data?.indicator.deployment_expired_count).toEqual(1);
    expect(indicator.data?.indicator.deployment_platforms_count).toEqual(0);
  });

  it('should reconcile zero counters of a deployed indicator from its relationships', async () => {
    const fullScan = async () => {
      let pass = await reconcileDeployedIndicatorCounters(testContext, 1000);
      let updated = pass.updated;
      while (!pass.done) {
        pass = await reconcileDeployedIndicatorCounters(testContext, 1000);
        updated += pass.updated;
      }
      return updated;
    };
    // The rolling scan resumes from its saved cursor: finish the current pass so the next one starts at the beginning
    await fullScan();
    const stored = await internalLoadById(testContext, ADMIN_USER, indicatorId) as unknown as { _index: string };
    const zeroAll = COUNTER_FIELDS.map((field) => `ctx._source.${field} = 0;`).join(' ');
    await elUpdate(testContext, stored._index, indicatorId, setCounterScript(zeroAll));
    expect(await fullScan()).toBeGreaterThanOrEqual(1);
    const indicator = await queryAsAdminWithSuccess({ query: INDICATOR_READ, variables: { id: indicatorId } });
    expect(indicator.data?.indicator.deployments_count).toEqual(1);
    expect(indicator.data?.indicator.deployment_expired_count).toEqual(1);
  });

  it('should reconcile stale counters, as after a security platform deletion cascading to its deployments', async () => {
    const stored = await internalLoadById(testContext, ADMIN_USER, indicatorId) as unknown as { _index: string };
    await elUpdate(testContext, stored._index, indicatorId, setCounterScript('ctx._source.deployment_failed_count = 7'));
    const updated = await reconcileAllIndicatorDeploymentCounters(testContext, 1, 1000);
    expect(updated).toBeGreaterThanOrEqual(1);
    const indicator = await queryAsAdminWithSuccess({ query: INDICATOR_READ, variables: { id: indicatorId } });
    expect(indicator.data?.indicator.deployment_failed_count).toEqual(0);
    // The rolling scan restarts from the beginning once the end is reached
    const page = await reconcileIndicatorDeploymentCounters(testContext, 1000);
    expect(page.done).toEqual(true);
    expect(page.checked).toBeGreaterThanOrEqual(1);
  });

  it('should start the removal grace period of a revoked indicator at its revocation, never at a later edit', async () => {
    const stored = await internalLoadById(testContext, ADMIN_USER, secondIndicatorId) as unknown as { _index: string; updated_at: string };
    const pair = () => findDeployedOn(testContext, ADMIN_USER, secondIndicatorId, platformId);
    // Two runs of the resumable scan with a one hour grace period: every live deployment is seen, whatever the saved cursor
    const scan = async () => {
      await flagExpiredDeployments(testContext, ADMIN_USER, 3600 * 1000, 5000);
      await flagExpiredDeployments(testContext, ADMIN_USER, 3600 * 1000, 5000);
    };
    const setIndicator = (revoked: boolean, updatedAt: string) => elUpdate(testContext, stored._index, secondIndicatorId, {
      script: { source: 'ctx._source.revoked = params.revoked; ctx._source.updated_at = params.updatedAt', lang: 'painless', params: { revoked, updatedAt } },
    });
    // Revoked, and last edited long before the grace period: its grace period starts when the revocation is recorded
    await setIndicator(true, '2026-01-01T00:00:00.000Z');
    try {
      const scannedFrom = Date.now();
      await scan();
      const recorded = await pair();
      expect(recorded?.deployment_status).not.toEqual('expired');
      expect(new Date(recorded?.removal_requested_at as string).getTime()).toBeGreaterThanOrEqual(scannedFrom);
      // The revocation event gives the time of the revocation itself
      const revokedAt = new Date(Date.now() - 60 * 1000).toISOString();
      await recordIndicatorRevocations(testContext, new Map([[secondIndicatorId, revokedAt]]));
      expect(new Date((await pair())?.removal_requested_at as string).toISOString()).toEqual(revokedAt);
    } finally {
      await setIndicator(false, stored.updated_at);
    }
    // Reinstated: the removal is no longer requested
    await scan();
    expect((await pair())?.removal_requested_at).toBeFalsy();
  });
});
