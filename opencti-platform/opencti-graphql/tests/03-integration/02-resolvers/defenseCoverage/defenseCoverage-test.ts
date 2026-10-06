import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from 'vitest';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER, getAuthUser, testContext, USER_EDITOR, USER_PARTICIPATE } from '../../../utils/testQuery';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { MARKING_TLP_RED } from '../../../../src/schema/identifier';
import { computeDefenseCoverage, defenseGapId } from '../../../../src/modules/defenseCoverage/defenseCoverage-compute';
import { trackPendingValidationRequests } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
import { defenseCoverageStreamHandler, defenseCoverageStreamStartFrom } from '../../../../src/manager/defenseCoverageManager';
import { consumeFullComputationRequest, listPendingValidationTrackings, queuePendingValidationTracking } from '../../../../src/modules/defenseCoverage/defenseCoverage-state';
import { type BasicStoreEntityDefenseGap, ENTITY_TYPE_DEFENSE_GAP } from '../../../../src/modules/defenseCoverage/defenseGap/defenseGap-types';
import { redisSetDefensePendingValidationTracking } from '../../../../src/database/redis';
import { fullEntitiesList, internalFindByIds } from '../../../../src/database/middleware-loader';
import * as streamHandler from '../../../../src/database/stream/stream-handler';
import * as securityCoverageDomain from '../../../../src/modules/securityCoverage/securityCoverage-domain';
import * as repository from '../../../../src/database/repository';
import * as telemetryManager from '../../../../src/manager/telemetryManager';
import * as defenseCoverageUtils from '../../../../src/modules/defenseCoverage/defenseCoverage-utils';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../../../../src/modules/securityCoverage/securityCoverage-types';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../../../src/modules/grouping/grouping-types';
import { FunctionalError } from '../../../../src/config/errors';
import type { BasicStoreEntity } from '../../../../src/types/store';
import { notifyDefenseLevelChanges } from '../../../../src/modules/defenseCoverage/defenseCoverage-notification';
import { addTrigger, triggerDelete } from '../../../../src/modules/notification/notification-domain';
import { ENTITY_TYPE_TRIGGER } from '../../../../src/modules/notification/notification-types';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { TriggerEventType, TriggerType } from '../../../../src/generated/graphql';
import { DEFENSE_THREAT_TYPES } from '../../../../src/modules/defenseCoverage/defenseCoverage-types';
import type { DefenseCoverage } from '../../../../src/modules/defenseCoverage/defenseCoverage-types';

const SIGMA_RULE = `title: Defense matrix test rule
id: 5f3c3f5a-1d2b-4c6e-9f0a-1234567890ab
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: 'defense-matrix-test.exe'
  condition: selection
level: high
`;

const STIX_DOMAIN_OBJECT_DELETE = gql`
  mutation StixDomainObjectDelete($id: ID!) {
    stixDomainObjectEdit(id: $id) { delete }
  }
`;
const ATTACK_PATTERN_ADD = gql`
  mutation AttackPatternAdd($input: AttackPatternAddInput!) {
    attackPatternAdd(input: $input) { id }
  }
`;
const DATA_COMPONENT_ADD = gql`
  mutation DataComponentAdd($input: DataComponentAddInput!) {
    dataComponentAdd(input: $input) { id }
  }
`;
const COURSE_OF_ACTION_ADD = gql`
  mutation CourseOfActionAdd($input: CourseOfActionAddInput!) {
    courseOfActionAdd(input: $input) { id }
  }
`;
const INTRUSION_SET_ADD = gql`
  mutation IntrusionSetAdd($input: IntrusionSetAddInput!) {
    intrusionSetAdd(input: $input) { id }
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
const INDICATOR_ADD = gql`
  mutation IndicatorAdd($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) { id x_opencti_rule_status x_opencti_rule_level x_opencti_rule_logsource { category product service } }
  }
`;
const INDICATOR_DELETE = gql`
  mutation IndicatorDelete($id: ID!) {
    indicatorDelete(id: $id)
  }
`;
const RELATIONSHIP_ADD = gql`
  mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) { id }
  }
`;
const DEFENSE_PLATFORMS = gql`
  query DefensePlatforms {
    defensePlatforms { id name entity_type security_platform_type }
  }
`;
const DEFENSE_MATRIX = gql`
  query DefenseMatrix($platformIds: [String!], $threatScope: DefenseThreatScope) {
    defenseMatrix(platformIds: $platformIds, threatScope: $threatScope) {
      computed_at
      threats_count
      levels
      cells {
        attack_pattern_id
        x_mitre_id
        level
        telemetry
        detection
        validated
        mitigated
        recommended_action
        threats_count
        platforms { platform_id level telemetry detection recommended_action data_components_count rules_count }
      }
    }
  }
`;
const THREATS_COUNT = gql`
  query DefenseThreatsCount($types: [String]) {
    stixDomainObjects(types: $types, first: 1) { pageInfo { globalCount } }
  }
`;
const DEFENSE_TECHNIQUE = gql`
  query DefenseTechnique($id: String!, $platformIds: [String!], $threatScope: DefenseThreatScope) {
    defenseTechnique(id: $id, platformIds: $platformIds, threatScope: $threatScope) {
      cell { level recommended_action }
      dataComponents { dataComponent { id } providedBy { id } }
      rules { indicator { id } deployments { platform { id } status } }
      mitigations { id }
      threats { threat { id } confidence }
      gaps { platform_id level last_validation_requested_at validation_requests { security_coverage_id grouping_id threat_id status } }
    }
  }
`;
const DEFENSE_GAPS = gql`
  query DefenseGaps($platformIds: [String!], $threatScope: DefenseThreatScope, $filter: DefenseGapsFilter) {
    defenseGaps(platformIds: $platformIds, threatScope: $threatScope, filter: $filter, first: 50) {
      edges { node { id attack_pattern_id platform_id level recommended_action threats_count priority last_validation_requested_at requiredDataComponents { id } ruleCandidates(first: 3) { id } } }
      pageInfo { globalCount hasNextPage }
      threats_count
    }
  }
`;
const DEFENSE_GAP_EXPORT = gql`
  query DefenseGapExport($platformIds: [String!], $threatScope: DefenseThreatScope, $filter: DefenseGapsFilter) {
    defenseGapExport(platformIds: $platformIds, threatScope: $threatScope, filter: $filter)
  }
`;
const ATTACK_PATTERNS_BY_LEVEL = gql`
  query AttackPatternsByLevel($filters: FilterGroup, $search: String) {
    attackPatterns(filters: $filters, search: $search, first: 50) { edges { node { id } } }
  }
`;
const DEFENSE_VALIDATE = gql`
  mutation DefenseValidate($input: DefenseValidationInput!) {
    defenseGapsValidate(input: $input) {
      gaps_count
      securityCoverage { id objectCovered { ... on Grouping { id } } externalReferences { edges { node { id source_name url } } } }
      grouping { id objects { edges { node { ... on BasicObject { id } } } } }
    }
  }
`;
const EXTERNAL_REFERENCE_DELETE = gql`
  mutation ExternalReferenceDelete($id: ID!) {
    externalReferenceEdit(id: $id) { delete }
  }
`;
const SECURITY_COVERAGE_DELETE = gql`
  mutation SecurityCoverageDelete($id: ID!) {
    securityCoverageDelete(id: $id)
  }
`;
const GROUPING_DELETE = gql`
  mutation GroupingDelete($id: ID!) {
    groupingDelete(id: $id)
  }
`;
const MAPPING_ADD = gql`
  mutation MappingAdd($input: DefenseLogsourceMappingAddInput!) {
    defenseLogsourceMappingAdd(input: $input) { id name built_in active data_components }
  }
`;
const MAPPING_PATCH = gql`
  mutation MappingPatch($id: ID!, $input: [EditInput!]!) {
    defenseLogsourceMappingFieldPatch(id: $id, input: $input) { id active description }
  }
`;
const MAPPING_DELETE = gql`
  mutation MappingDelete($id: ID!) {
    defenseLogsourceMappingDelete(id: $id)
  }
`;
const MAPPINGS = gql`
  query Mappings($search: String) {
    defenseLogsourceMappings(search: $search, first: 100) { edges { node { id name built_in active logsource_category logsource_product } } }
  }
`;
const PROVIDES_FROM_LOGSOURCES = gql`
  mutation ProvidesFromLogsources($id: ID!, $logsources: [DefenseLogsourceInput!]!) {
    defensePlatformProvidesFromLogsources(id: $id, logsources: $logsources) {
      created_count
      existing_count
      unmatched_data_components
      dataComponents { id }
    }
  }
`;
const RECOMPUTE = gql`
  mutation Recompute {
    defenseCoverageRecompute
  }
`;
const STATUS = gql`
  query Status {
    defenseCoverageStatus { computed_at full_computation_requested validation_available }
  }
`;

const LEVEL_DETECTION_AVAILABLE = 2;
const MITRE_ID = 'T9901';

describe('Threat-informed defense matrix', () => {
  const created: { [key: string]: string } = {};
  let securityCoverageId: string | undefined;
  let groupingId: string | undefined;
  let mappingId: string | undefined;
  let externalReferenceId: string | undefined;
  let lastRequestedAt: string | undefined;

  const relate = async (fromId: string, toId: string, relationship_type: string) => {
    const result = await queryAsAdminWithSuccess({ query: RELATIONSHIP_ADD, variables: { input: { fromId, toId, relationship_type, confidence: 80 } } });
    return result.data?.stixCoreRelationshipAdd.id as string;
  };
  const scope = (threatIds: string[]) => ({ mode: 'SELECTED', threatIds });
  // Validation requests need an active OpenAEV connector: the suite stands one in without registering a connector
  const connectorsForEnrichment = repository.connectorsForEnrichment;
  let validationConnectors: MockInstance<typeof repository.connectorsForEnrichment> | undefined;

  beforeAll(async () => {
    validationConnectors = vi.spyOn(repository, 'connectorsForEnrichment').mockImplementation(async (context, user, connectorScope, ...rest) => {
      return connectorScope === ENTITY_TYPE_SECURITY_COVERAGE
        ? [{ id: 'defense-matrix-test-openaev', active: true }]
        : connectorsForEnrichment(context, user, connectorScope, ...rest);
    });
    const attackPattern = await queryAsAdminWithSuccess({
      query: ATTACK_PATTERN_ADD,
      variables: { input: { name: 'Defense matrix test technique', x_mitre_id: MITRE_ID, description: 'Defense matrix integration test' } },
    });
    created.attackPattern = attackPattern.data?.attackPatternAdd.id;
    const dataComponent = await queryAsAdminWithSuccess({ query: DATA_COMPONENT_ADD, variables: { input: { name: 'Defense matrix test telemetry' } } });
    created.dataComponent = dataComponent.data?.dataComponentAdd.id;
    const mappedComponent = await queryAsAdminWithSuccess({ query: DATA_COMPONENT_ADD, variables: { input: { name: 'Defense matrix mapped telemetry' } } });
    created.mappedComponent = mappedComponent.data?.dataComponentAdd.id;
    const courseOfAction = await queryAsAdminWithSuccess({ query: COURSE_OF_ACTION_ADD, variables: { input: { name: 'Defense matrix test mitigation' } } });
    created.courseOfAction = courseOfAction.data?.courseOfActionAdd.id;
    const threat = await queryAsAdminWithSuccess({ query: INTRUSION_SET_ADD, variables: { input: { name: 'Defense matrix test threat' } } });
    created.threat = threat.data?.intrusionSetAdd.id;
    const restrictedThreat = await queryAsAdminWithSuccess({
      query: INTRUSION_SET_ADD,
      variables: { input: { name: 'Defense matrix restricted threat', objectMarking: [MARKING_TLP_RED] } },
    });
    created.restrictedThreat = restrictedThreat.data?.intrusionSetAdd.id;
    const platform = await queryAsAdminWithSuccess({ query: PLATFORM_ADD, variables: { input: { name: 'Defense matrix test EDR', security_platform_type: 'EDR' } } });
    created.platform = platform.data?.securityPlatformAdd.id;
    const indicator = await queryAsAdminWithSuccess({
      query: INDICATOR_ADD,
      variables: {
        input: {
          name: 'Defense matrix test rule',
          pattern: SIGMA_RULE,
          pattern_type: 'sigma',
          x_opencti_rule_status: 'test',
          x_opencti_rule_level: 'high',
          x_opencti_rule_logsource: { category: 'process_creation', product: 'windows' },
        },
      },
    });
    created.indicator = indicator.data?.indicatorAdd.id;
    expect(indicator.data?.indicatorAdd.x_opencti_rule_status).toEqual('test');
    expect(indicator.data?.indicatorAdd.x_opencti_rule_logsource).toEqual({ category: 'process_creation', product: 'windows', service: null });

    await relate(created.dataComponent, created.attackPattern, 'detects');
    await relate(created.platform, created.dataComponent, 'provides');
    created.indicates = await relate(created.indicator, created.attackPattern, 'indicates');
    await relate(created.courseOfAction, created.attackPattern, 'mitigates');
    await relate(created.threat, created.attackPattern, 'uses');
    created.restrictedUses = await relate(created.restrictedThreat, created.attackPattern, 'uses');
    await computeDefenseCoverage(testContext, SYSTEM_USER, {});
  });

  afterAll(async () => {
    validationConnectors?.mockRestore();
    if (securityCoverageId) await queryAsAdminWithSuccess({ query: SECURITY_COVERAGE_DELETE, variables: { id: securityCoverageId } });
    if (externalReferenceId) await queryAsAdminWithSuccess({ query: EXTERNAL_REFERENCE_DELETE, variables: { id: externalReferenceId } });
    if (groupingId) await queryAsAdminWithSuccess({ query: GROUPING_DELETE, variables: { id: groupingId } });
    if (mappingId) await queryAsAdminWithSuccess({ query: MAPPING_DELETE, variables: { id: mappingId } });
    if (created.indicator) await queryAsAdminWithSuccess({ query: INDICATOR_DELETE, variables: { id: created.indicator } });
    if (created.platform) await queryAsAdminWithSuccess({ query: PLATFORM_DELETE, variables: { id: created.platform } });
    const domainObjects = ['attackPattern', 'dataComponent', 'mappedComponent', 'courseOfAction', 'threat', 'restrictedThreat'];
    for (let index = 0; index < domainObjects.length; index += 1) {
      const id = created[domainObjects[index]];
      if (id) await queryAsAdminWithSuccess({ query: STIX_DOMAIN_OBJECT_DELETE, variables: { id } });
    }
    await computeDefenseCoverage(testContext, SYSTEM_USER, {});
  });

  it('should list the security platforms of the matrix', async () => {
    const result = await queryAsAdminWithSuccess({ query: DEFENSE_PLATFORMS });
    const platform = result.data?.defensePlatforms.find((p: { id: string }) => p.id === created.platform);
    expect(platform).toEqual({ id: created.platform, name: 'Defense matrix test EDR', entity_type: 'SecurityPlatform', security_platform_type: 'EDR' });
  });

  it('should compute the defense level of a technique on a security platform', async () => {
    const result = await queryAsAdminWithSuccess({ query: DEFENSE_MATRIX, variables: { platformIds: [created.platform], threatScope: scope([created.threat]) } });
    const matrix = result.data?.defenseMatrix;
    expect(matrix.computed_at).toBeDefined();
    expect(matrix.threats_count).toEqual(1);
    const cell = matrix.cells.find((c: { attack_pattern_id: string }) => c.attack_pattern_id === created.attackPattern);
    expect(cell.x_mitre_id).toEqual(MITRE_ID);
    // A rule known in OpenCTI and deployed nowhere the platform records: detection available
    expect(cell.level).toEqual(LEVEL_DETECTION_AVAILABLE);
    expect(cell.telemetry).toBe(true);
    expect(cell.detection).toEqual('available');
    expect(cell.validated).toEqual('none');
    expect(cell.mitigated).toBe(true);
    expect(cell.recommended_action).toEqual('deploy_rule');
    expect(cell.threats_count).toEqual(1);
    expect(cell.platforms).toEqual([expect.objectContaining({
      platform_id: created.platform,
      level: LEVEL_DETECTION_AVAILABLE,
      telemetry: true,
      detection: 'available',
      recommended_action: 'deploy_rule',
      data_components_count: 1,
      rules_count: 0,
    })]);
  });

  it('should count every accessible threat in the ALL scope, those using no technique included', async () => {
    const threats = await queryAsAdminWithSuccess({ query: THREATS_COUNT, variables: { types: DEFENSE_THREAT_TYPES } });
    const result = await queryAsAdminWithSuccess({ query: DEFENSE_MATRIX, variables: { platformIds: [created.platform], threatScope: { mode: 'ALL' } } });
    expect(result.data?.defenseMatrix.threats_count).toEqual(threats.data?.stixDomainObjects.pageInfo.globalCount);
  });

  it('should keep the stored aggregate out of the attack pattern attributes', async () => {
    const filters = { mode: 'and', filters: [{ key: ['defense_level'], values: [String(LEVEL_DETECTION_AVAILABLE)], operator: 'gte' }], filterGroups: [] };
    await queryAsAdminWithError(
      { query: ATTACK_PATTERNS_BY_LEVEL, variables: { filters, search: 'Defense matrix test technique' } },
      'Incorrect filter keys not existing in any schema definition',
    );
  });

  it('should explain the level with every evidence', async () => {
    const result = await queryAsAdminWithSuccess({
      query: DEFENSE_TECHNIQUE,
      variables: { id: created.attackPattern, platformIds: [created.platform], threatScope: scope([created.threat]) },
    });
    const technique = result.data?.defenseTechnique;
    expect(technique.cell.level).toEqual(LEVEL_DETECTION_AVAILABLE);
    expect(technique.dataComponents).toEqual([{ dataComponent: { id: created.dataComponent }, providedBy: [{ id: created.platform }] }]);
    expect(technique.rules).toEqual([{ indicator: { id: created.indicator }, deployments: [] }]);
    expect(technique.mitigations).toEqual([{ id: created.courseOfAction }]);
    expect(technique.threats).toEqual([{ threat: { id: created.threat }, confidence: 80 }]);
  });

  it('should never reveal a threat the reader cannot see in the overlay', async () => {
    const variables = { platformIds: [created.platform], threatScope: scope([created.threat, created.restrictedThreat]) };
    const asAdmin = await queryAsAdminWithSuccess({ query: DEFENSE_MATRIX, variables });
    const adminCell = asAdmin.data?.defenseMatrix.cells.find((c: { attack_pattern_id: string }) => c.attack_pattern_id === created.attackPattern);
    expect(adminCell.threats_count).toEqual(2);
    const asGreenUser = await queryAsUserWithSuccess(USER_PARTICIPATE, { query: DEFENSE_MATRIX, variables });
    expect(asGreenUser.data?.defenseMatrix.threats_count).toEqual(1);
    const userCell = asGreenUser.data?.defenseMatrix.cells.find((c: { attack_pattern_id: string }) => c.attack_pattern_id === created.attackPattern);
    expect(userCell.threats_count).toEqual(1);
  });

  it('should list the technique in the gap backlog with its priority and export it', async () => {
    const variables = { platformIds: [created.platform], threatScope: scope([created.threat]), filter: { search: MITRE_ID } };
    const result = await queryAsAdminWithSuccess({ query: DEFENSE_GAPS, variables });
    const gaps = result.data?.defenseGaps.edges.map((e: { node: unknown }) => e.node);
    expect(result.data?.defenseGaps.pageInfo.globalCount).toEqual(1);
    expect(result.data?.defenseGaps.threats_count).toEqual(1);
    expect(gaps[0]).toEqual(expect.objectContaining({
      attack_pattern_id: created.attackPattern,
      platform_id: created.platform,
      level: LEVEL_DETECTION_AVAILABLE,
      recommended_action: 'deploy_rule',
      threats_count: 1,
      // The platform provides the detecting telemetry and the only rule is the one to deploy on it
      requiredDataComponents: [],
      ruleCandidates: [{ id: created.indicator }],
    }));
    expect(gaps[0].priority).toBeGreaterThan(0);
    // A platform requested twice is one scope entry
    const duplicated = await queryAsAdminWithSuccess({ query: DEFENSE_GAPS, variables: { ...variables, platformIds: [created.platform, created.platform] } });
    expect(duplicated.data?.defenseGaps.pageInfo.globalCount).toEqual(1);
    const usedOnly = await queryAsAdminWithSuccess({ query: DEFENSE_GAPS, variables: { ...variables, threatScope: { mode: 'NONE' }, filter: { search: MITRE_ID, onlyUsedByThreats: true } } });
    expect(usedOnly.data?.defenseGaps.edges).toEqual([]);
    expect(usedOnly.data?.defenseGaps.threats_count).toEqual(0);
    const csv = await queryAsAdminWithSuccess({ query: DEFENSE_GAP_EXPORT, variables });
    const lines = (csv.data?.defenseGapExport as string).trim().split('\n');
    expect(lines[0]).toContain('technique_id');
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain(MITRE_ID);
    expect(lines[1]).toContain('Defense matrix test EDR');
    // The export is built: a usage counter that cannot be written does not fail it
    const counter = vi.spyOn(telemetryManager, 'addDefenseGapExportCount').mockRejectedValueOnce(new Error('telemetry unavailable'));
    try {
      const counted = await queryAsAdminWithSuccess({ query: DEFENSE_GAP_EXPORT, variables });
      expect((counted.data?.defenseGapExport as string).trim().split('\n')).toHaveLength(2);
      expect(counter).toHaveBeenCalledTimes(1);
    } finally {
      counter.mockRestore();
    }
  });

  it('should validate the technique through a security coverage of a grouping', async () => {
    const input = {
      attackPatternIds: [created.attackPattern],
      platformIds: [created.platform],
      threatId: created.threat,
      name: 'Defense matrix test validation',
      external_reference_url: ' https://risk.example.com/scenarios/defense-matrix-test ',
    };
    // Without an active OpenAEV connector the request is refused before anything is created
    validationConnectors?.mockResolvedValueOnce([]);
    await queryAsAdminWithError({ query: DEFENSE_VALIDATE, variables: { input } }, 'No active OpenAEV connector can validate techniques: connect OpenAEV to this platform first');
    const result = await queryAsAdminWithSuccess({ query: DEFENSE_VALIDATE, variables: { input } });
    const validation = result.data?.defenseGapsValidate;
    securityCoverageId = validation.securityCoverage.id;
    groupingId = validation.grouping.id;
    expect(validation.gaps_count).toEqual(2);
    expect(validation.securityCoverage.objectCovered.id).toEqual(groupingId);
    const references = validation.securityCoverage.externalReferences.edges.map((e: { node: { id: string; source_name: string; url: string } }) => e.node);
    externalReferenceId = references[0]?.id;
    expect(references).toEqual([{ id: externalReferenceId, source_name: 'risk.example.com', url: 'https://risk.example.com/scenarios/defense-matrix-test' }]);
    const objectIds = validation.grouping.objects.edges.map((e: { node: { id: string } }) => e.node.id);
    // The grouping records the security platform whose gaps track the request next to the technique and the threat
    expect(objectIds.length).toEqual(3);
    expect(objectIds).toEqual(expect.arrayContaining([created.attackPattern, created.threat, created.platform]));
    const technique = await queryAsAdminWithSuccess({ query: DEFENSE_TECHNIQUE, variables: { id: created.attackPattern, platformIds: [created.platform] } });
    const platformGap = technique.data?.defenseTechnique.gaps.find((g: { platform_id: string }) => g.platform_id === created.platform);
    expect(platformGap.validation_requests).toEqual([{ security_coverage_id: securityCoverageId, grouping_id: groupingId, threat_id: created.threat, status: 'waiting' }]);
    lastRequestedAt = platformGap.last_validation_requested_at;
    expect(lastRequestedAt).toBeTruthy();
    // A recomputation refreshes the computed fields of the gap and keeps its validation requests
    await computeDefenseCoverage(testContext, SYSTEM_USER, { attackPatternIds: [created.attackPattern] });
    const recomputed = await queryAsAdminWithSuccess({ query: DEFENSE_TECHNIQUE, variables: { id: created.attackPattern, platformIds: [created.platform] } });
    const recomputedGap = recomputed.data?.defenseTechnique.gaps.find((g: { platform_id: string }) => g.platform_id === created.platform);
    expect(recomputedGap.level).toEqual(platformGap.level);
    expect(recomputedGap.validation_requests).toEqual([{ security_coverage_id: securityCoverageId, grouping_id: groupingId, threat_id: created.threat, status: 'waiting' }]);
  });

  it('should track a validation request queued after a failed tracking at the next manager run', async () => {
    const queuedCoverageId = 'defense-matrix-test-queued-coverage';
    const unreadableId = 'defense-matrix-test-unreadable-tracking';
    const request = { security_coverage_id: queuedCoverageId, grouping_id: groupingId as string, requested_at: new Date().toISOString(), requested_by: ADMIN_USER.id };
    const targets = [{ attackPatternId: created.attackPattern, platformId: created.platform }];
    await queuePendingValidationTracking({ request, targets });
    await redisSetDefensePendingValidationTracking(unreadableId, 'not a tracking');
    await trackPendingValidationRequests(testContext);
    // Tracking the same request again never appends it twice
    await queuePendingValidationTracking({ request, targets });
    await trackPendingValidationRequests(testContext);
    const queuedIds = (await listPendingValidationTrackings()).map((entry) => entry.id);
    expect(queuedIds).not.toContain(queuedCoverageId);
    expect(queuedIds).not.toContain(unreadableId);
    const gapId = defenseGapId(created.attackPattern, created.platform).internalId;
    const records = await internalFindByIds<BasicStoreEntityDefenseGap>(testContext, SYSTEM_USER, [gapId], { type: ENTITY_TYPE_DEFENSE_GAP }) as BasicStoreEntityDefenseGap[];
    const requests = (records[0]?.validation_requests ?? []).filter((tracked) => tracked.security_coverage_id === queuedCoverageId);
    expect(requests).toEqual([request]);
    expect(records[0]?.last_validation_requested_at).toEqual(request.requested_at);
    // A reader never sees a tracked request whose Security Coverage he cannot access, nor its date
    const technique = await queryAsAdminWithSuccess({ query: DEFENSE_TECHNIQUE, variables: { id: created.attackPattern, platformIds: [created.platform] } });
    const platformGap = technique.data?.defenseTechnique.gaps.find((g: { platform_id: string }) => g.platform_id === created.platform);
    expect(platformGap.validation_requests).toEqual([{ security_coverage_id: securityCoverageId, grouping_id: groupingId, threat_id: created.threat, status: 'waiting' }]);
    expect(platformGap.last_validation_requested_at).toEqual(lastRequestedAt);
  });

  it('should leave no grouping behind when the security coverage of a validation request cannot be created', async () => {
    const name = 'Defense matrix test failed validation';
    // Neither streamed nor kept: the raw stream counts of the suite are unchanged
    const mocks = [
      vi.spyOn(streamHandler, 'storeCreateEntityEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeCreateRelationEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeUpdateEvent').mockResolvedValue(undefined as never),
      vi.spyOn(streamHandler, 'storeDeleteEvent').mockResolvedValue(undefined as never),
      vi.spyOn(securityCoverageDomain, 'addSecurityCoverage').mockRejectedValue(FunctionalError('Defense matrix test coverage failure')),
    ];
    try {
      await queryAsAdminWithError(
        { query: DEFENSE_VALIDATE, variables: { input: { attackPatternIds: [created.attackPattern], name } } },
        'Defense matrix test coverage failure',
      );
    } finally {
      mocks.forEach((mock) => mock.mockRestore());
    }
    const groupings = await fullEntitiesList<BasicStoreEntity>(testContext, SYSTEM_USER, [ENTITY_TYPE_CONTAINER_GROUPING]);
    expect(groupings.filter((grouping) => grouping.name === name)).toEqual([]);
  });

  it('should refuse a validation request tracked on more gaps than the limit before anything is created', async () => {
    const name = 'Defense matrix test oversized validation';
    // Every requested platform multiplies the gaps of a request: reaching the limit for real takes ten platforms and 200 techniques
    const oversized = Array.from({ length: 2001 }, (_, index) => ({ attackPatternId: created.attackPattern, platformId: `defense-matrix-test-platform-${index}` }));
    const targets = vi.spyOn(defenseCoverageUtils, 'buildValidationTargets').mockReturnValueOnce(oversized);
    try {
      await queryAsAdminWithError(
        { query: DEFENSE_VALIDATE, variables: { input: { attackPatternIds: [created.attackPattern], name } } },
        'A validation request cannot be tracked on more than 2000 gaps: validate fewer techniques or security platforms',
      );
    } finally {
      targets.mockRestore();
    }
    const groupings = await fullEntitiesList<BasicStoreEntity>(testContext, SYSTEM_USER, [ENTITY_TYPE_CONTAINER_GROUPING]);
    expect(groupings.filter((grouping) => grouping.name === name)).toEqual([]);
  });

  it('should reject an empty or unknown validation request', async () => {
    await queryAsAdminWithError({ query: DEFENSE_VALIDATE, variables: { input: { attackPatternIds: [] } } }, 'Select at least one technique to validate');
    await queryAsAdminWithError(
      { query: DEFENSE_VALIDATE, variables: { input: { attackPatternIds: [created.attackPattern], platformIds: ['unknown-platform'] } } },
      'Some security platforms of the validation request cannot be found',
    );
    await queryAsAdminWithError(
      { query: DEFENSE_VALIDATE, variables: { input: { attackPatternIds: [created.attackPattern], external_reference_url: 'javascript:alert(1)' } } },
      'The external reference of a validation request must be an http or https URL',
    );
    await queryAsAdminWithError(
      { query: DEFENSE_VALIDATE, variables: { input: { attackPatternIds: [created.attackPattern], name: '   ' } } },
      'The name of a validation request must contain at least 2 characters other than spaces',
    );
  });

  it('should manage custom telemetry mappings and protect the built-in ones', async () => {
    const added = await queryAsAdminWithSuccess({
      query: MAPPING_ADD,
      variables: { input: { logsource_product: 'defense-matrix-test', data_components: ['Defense matrix mapped telemetry', ' '], description: 'Integration test' } },
    });
    mappingId = added.data?.defenseLogsourceMappingAdd.id;
    expect(added.data?.defenseLogsourceMappingAdd).toEqual(expect.objectContaining({ built_in: false, active: true, data_components: ['Defense matrix mapped telemetry'] }));
    await queryAsAdminWithError(
      { query: MAPPING_ADD, variables: { input: { logsource_product: 'defense-matrix-test', data_components: ['Other'] } } },
      'A mapping already exists for this log source',
    );
    const patched = await queryAsAdminWithSuccess({ query: MAPPING_PATCH, variables: { id: mappingId, input: [{ key: 'description', value: ['Updated'] }] } });
    expect(patched.data?.defenseLogsourceMappingFieldPatch.description).toEqual('Updated');
    await queryAsAdminWithError(
      { query: MAPPING_PATCH, variables: { id: mappingId, input: [{ key: 'logsource_product', value: ['other'] }] } },
      'Only the data components, the description and the activation of a log source mapping can be updated',
    );
    const builtIns = await queryAsAdminWithSuccess({ query: MAPPINGS, variables: { search: 'process_creation' } });
    const builtIn = builtIns.data?.defenseLogsourceMappings.edges.map((e: { node: { id: string; built_in: boolean } }) => e.node).find((m: { built_in: boolean }) => m.built_in);
    expect(builtIn).toBeDefined();
    await queryAsAdminWithError({ query: MAPPING_DELETE, variables: { id: builtIn.id } }, 'Built-in log source mappings cannot be deleted, deactivate them instead');
  });

  it('should declare the telemetry of a platform from its log sources', async () => {
    const result = await queryAsAdminWithSuccess({
      query: PROVIDES_FROM_LOGSOURCES,
      variables: { id: created.platform, logsources: [{ product: 'defense-matrix-test' }] },
    });
    const provides = result.data?.defensePlatformProvidesFromLogsources;
    expect(provides.created_count).toEqual(1);
    expect(provides.existing_count).toEqual(0);
    expect(provides.dataComponents).toEqual([{ id: created.mappedComponent }]);
    expect(provides.unmatched_data_components).toEqual([]);
    // Declaring the same log source again creates nothing and says so
    const again = await queryAsAdminWithSuccess({
      query: PROVIDES_FROM_LOGSOURCES,
      variables: { id: created.platform, logsources: [{ product: 'defense-matrix-test' }] },
    });
    expect(again.data?.defensePlatformProvidesFromLogsources.created_count).toEqual(0);
    expect(again.data?.defensePlatformProvidesFromLogsources.existing_count).toEqual(1);
    expect(again.data?.defensePlatformProvidesFromLogsources.dataComponents).toEqual([{ id: created.mappedComponent }]);
    await queryAsAdminWithError({ query: PROVIDES_FROM_LOGSOURCES, variables: { id: created.platform, logsources: [] } }, 'Provide between 1 and 200 log sources');
  });

  it('should request a full computation', async () => {
    const result = await queryAsAdminWithSuccess({ query: RECOMPUTE });
    expect(result.data?.defenseCoverageRecompute).toBe(true);
    const status = await queryAsAdminWithSuccess({ query: STATUS });
    expect(status.data?.defenseCoverageStatus.full_computation_requested).toBe(true);
    expect(typeof status.data?.defenseCoverageStatus.validation_available).toBe('boolean');
    // Read and reset in one step: the manager consumes a request once
    expect(await consumeFullComputationRequest()).toBe(true);
    expect(await consumeFullComputationRequest()).toBe(false);
    const consumed = await queryAsAdminWithSuccess({ query: STATUS });
    expect(consumed.data?.defenseCoverageStatus.full_computation_requested).toBe(false);
  });

  it('should resume the defense coverage stream after the last handled event when the manager restarts', async () => {
    await defenseCoverageStreamHandler([], '1791000000000-0');
    expect(await defenseCoverageStreamStartFrom()).toEqual('1791000000000-0');
    await defenseCoverageStreamHandler([], '1791000000001-0');
    expect(await defenseCoverageStreamStartFrom()).toEqual('1791000000001-0');
    // A batch without an event id keeps the position of the last handled one
    await defenseCoverageStreamHandler([]);
    expect(await defenseCoverageStreamStartFrom()).toEqual('1791000000001-0');
  });

  const triggerFilters = JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], values: ['Attack-Pattern'], operator: 'eq', mode: 'or' }], filterGroups: [] });
  const coverageWithRules = (rules: { id: string; rel: string }[]) => ({
    computed_at: '2026-10-01T00:00:00.000Z',
    level: rules.length > 0 ? LEVEL_DETECTION_AVAILABLE : 0,
    data_components: [],
    rules,
    mitigations: [],
    validations: [],
    platforms: [],
  }) as DefenseCoverage;
  const coverageChange = (previous: DefenseCoverage, coverage: DefenseCoverage) => ({ attack_pattern_id: created.attackPattern, previous, coverage });

  it('should notify the live triggers listening to a defense level change', async () => {
    const trigger = await addTrigger(testContext, ADMIN_USER, {
      name: 'Defense matrix test - level decreased',
      event_types: [TriggerEventType.DefenseLevelDecreased],
      instance_trigger: false,
      recipients: [],
      filters: triggerFilters,
    }, TriggerType.Live);
    resetCacheForEntity(ENTITY_TYPE_TRIGGER);
    try {
      const rule = [{ id: created.indicator, rel: created.indicates }];
      expect(await notifyDefenseLevelChanges(testContext, [coverageChange(coverageWithRules(rule), coverageWithRules([]))])).toEqual(1);
      // A retried change skips the triggers its failed delivery already handled
      const retried = { ...coverageChange(coverageWithRules(rule), coverageWithRules([])), delivered_trigger_ids: [trigger.id] };
      expect(await notifyDefenseLevelChanges(testContext, [retried])).toEqual(0);
      // The trigger listens to decreases only
      expect(await notifyDefenseLevelChanges(testContext, [coverageChange(coverageWithRules([]), coverageWithRules(rule))])).toEqual(0);
      // A recomputation without any change notifies nobody
      await computeDefenseCoverage(testContext, SYSTEM_USER, { attackPatternIds: [created.attackPattern] });
      const unchanged = await computeDefenseCoverage(testContext, SYSTEM_USER, { attackPatternIds: [created.attackPattern] });
      expect(unchanged.level_changes).toEqual(0);
      expect(unchanged.notified).toEqual(0);
      // and writes no gap: their computed values are the stored ones
      expect(unchanged.gaps).toBeGreaterThan(0);
      expect(unchanged.written_gaps).toEqual(0);
    } finally {
      await triggerDelete(testContext, ADMIN_USER, trigger.id);
      resetCacheForEntity(ENTITY_TYPE_TRIGGER);
    }
  });

  it('should only tell a recipient the level change they can see', async () => {
    const participant = await getAuthUser(USER_PARTICIPATE.id);
    const trigger = await addTrigger(testContext, participant, {
      name: 'Defense matrix test - level increased',
      event_types: [TriggerEventType.DefenseLevelIncreased],
      instance_trigger: false,
      recipients: [],
      filters: triggerFilters,
    }, TriggerType.Live);
    resetCacheForEntity(ENTITY_TYPE_TRIGGER);
    try {
      const restrictedRule = [{ id: created.restrictedThreat, rel: created.restrictedUses }];
      const visibleRule = [{ id: created.indicator, rel: created.indicates }];
      // The aggregate level rises only because of an evidence the recipient cannot access
      expect(await notifyDefenseLevelChanges(testContext, [coverageChange(coverageWithRules([]), coverageWithRules(restrictedRule))])).toEqual(0);
      // The aggregate level does not move, while the level the recipient sees rises
      const change = coverageChange(coverageWithRules(restrictedRule), coverageWithRules([...restrictedRule, ...visibleRule]));
      expect(await notifyDefenseLevelChanges(testContext, [change])).toEqual(1);
    } finally {
      await triggerDelete(testContext, participant, trigger.id);
      resetCacheForEntity(ENTITY_TYPE_TRIGGER);
    }
  });

  it('should enforce the capabilities of every surface', async () => {
    await queryAsUserWithSuccess(USER_PARTICIPATE, { query: DEFENSE_PLATFORMS });
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
      query: DEFENSE_VALIDATE,
      variables: { input: { attackPatternIds: [created.attackPattern] } },
    });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: RECOMPUTE });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: MAPPINGS, variables: {} });
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
      query: PROVIDES_FROM_LOGSOURCES,
      variables: { id: created.platform, logsources: [{ product: 'defense-matrix-test' }] },
    });
  });
});
