import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { checkStixCoreRelationshipMapping } from '../../../../src/database/stix';
import { isStixCoreRelationship, RELATION_DEPLOYED_ON } from '../../../../src/schema/stixCoreRelationship';
import { ENTITY_TYPE_INDICATOR } from '../../../../src/modules/indicator/indicator-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../../src/modules/securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import {
  buildDeployedOnCreationData,
  isDeploymentStatus,
  isReadableWithIndicator,
  isValidationStatus,
  pairMarkings,
} from '../../../../src/modules/indicatorDeployment/indicatorDeployment-utils';
import { convertDeployedOnToStixExtension } from '../../../../src/modules/indicatorDeployment/indicatorDeployment-converter';
import type { StoreRelation } from '../../../../src/types/store';

describe('deployed-on relationship definition', () => {
  it('should be a STIX core relationship from Indicator to Security Platform only', () => {
    expect(RELATION_DEPLOYED_ON).toEqual('deployed-on');
    expect(isStixCoreRelationship(RELATION_DEPLOYED_ON)).toEqual(true);
    expect(checkStixCoreRelationshipMapping(ENTITY_TYPE_INDICATOR, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, RELATION_DEPLOYED_ON)).toEqual(true);
    expect(checkStixCoreRelationshipMapping(ENTITY_TYPE_INDICATOR, ENTITY_TYPE_MALWARE, RELATION_DEPLOYED_ON)).toEqual(false);
    expect(checkStixCoreRelationshipMapping(ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, ENTITY_TYPE_INDICATOR, RELATION_DEPLOYED_ON)).toEqual(false);
  });

  it('should register the lifecycle attributes on deployed-on only', () => {
    const attributes = schemaAttributesDefinition.getAttributeNames(RELATION_DEPLOYED_ON);
    const expected = [
      'deployment_status',
      'external_id',
      'deployed_at',
      'last_sync_at',
      'removed_at',
      'hit_count',
      'first_hit_at',
      'last_hit_at',
      'validation_status',
      'last_validation_at',
      'validation_run_id',
      'error_message',
    ];
    expected.forEach((name) => expect(attributes).toContain(name));
    // Common relationship attributes are kept
    expect(attributes).toContain('start_time');
    expect(attributes).toContain('description');
    // Other relationship types are not polluted
    const usesAttributes = schemaAttributesDefinition.getAttributeNames('uses');
    expect(usesAttributes).not.toContain('deployment_status');
    expect(usesAttributes).not.toContain('hit_count');
  });

  it('should replace the report ids of the last hit on an upsert, as they belong to the instant of the last hit', () => {
    const reportIds = schemaAttributesDefinition.getAttribute(RELATION_DEPLOYED_ON, 'last_hit_report_ids');
    expect(reportIds?.multiple).toEqual(true);
    expect(reportIds?.upsert).toEqual(true);
    expect(reportIds?.upsert_force_replace).toEqual(true);
  });

  it('should register filterable enum statuses with the exact plan values', () => {
    const deploymentStatus = schemaAttributesDefinition.getAttribute(RELATION_DEPLOYED_ON, 'deployment_status');
    expect(deploymentStatus?.isFilterable).toEqual(true);
    expect(deploymentStatus?.type === 'string' && deploymentStatus.format === 'enum' ? deploymentStatus.values : [])
      .toEqual(['pending', 'deployed', 'active', 'failed', 'removed', 'expired']);
    const validationStatus = schemaAttributesDefinition.getAttribute(RELATION_DEPLOYED_ON, 'validation_status');
    expect(validationStatus?.type === 'string' && validationStatus.format === 'enum' ? validationStatus.values : [])
      .toEqual(['not_requested', 'requested', 'detected', 'prevented', 'missed', 'error']);
  });

  it('should register the derived filterable counters on Indicator', () => {
    [
      'deployments_count',
      'deployment_platforms_count',
      'deployment_failed_count',
      'deployment_expired_count',
      'validated_platforms_count',
      'hit_platforms_count',
    ].forEach((name) => {
      const attribute = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_INDICATOR, name);
      expect(attribute?.type).toEqual('numeric');
      expect(attribute?.isFilterable).toEqual(true);
      expect(attribute?.update).toEqual(false);
    });
  });
});

describe('deployed-on creation data', () => {
  it('should apply defaults for status and counters', () => {
    expect(buildDeployedOnCreationData({})).toEqual({
      deployment_status: 'pending',
      hit_count: 0,
      validation_status: 'not_requested',
    });
  });

  it('should keep valid values and drop empty optional ones', () => {
    const data = buildDeployedOnCreationData({
      deployment_status: 'active',
      hit_count: 3.7,
      validation_status: 'detected',
      external_id: 'ti-123',
      error_message: '',
      deployed_at: '2026-10-01T00:00:00.000Z',
      removed_at: null,
    });
    expect(data).toEqual({
      deployment_status: 'active',
      hit_count: 3,
      validation_status: 'detected',
      external_id: 'ti-123',
      deployed_at: '2026-10-01T00:00:00.000Z',
    });
  });

  it('should keep the report ids of the last hit, so a retried report is recognized on a new deployment', () => {
    const data = buildDeployedOnCreationData({ last_hit_at: '2026-10-03T10:00:00.000Z', last_hit_report_ids: ['hits-report-1'] });
    expect(data.last_hit_report_ids).toEqual(['hits-report-1']);
    expect(buildDeployedOnCreationData({ last_hit_report_ids: [] })).not.toHaveProperty('last_hit_report_ids');
  });

  it('should reject unknown statuses and negative counters', () => {
    const data = buildDeployedOnCreationData({ deployment_status: 'live', validation_status: 'ok', hit_count: -2 });
    expect(data.deployment_status).toEqual('pending');
    expect(data.validation_status).toEqual('not_requested');
    expect(data.hit_count).toEqual(0);
    expect(isDeploymentStatus('expired')).toEqual(true);
    expect(isDeploymentStatus('EXPIRED')).toEqual(false);
    expect(isValidationStatus('missed')).toEqual(true);
    expect(isValidationStatus(undefined)).toEqual(false);
  });
});

describe('deployed-on STIX extension', () => {
  it('should export the lifecycle for deployed-on relationships', () => {
    const extension = convertDeployedOnToStixExtension({
      relationship_type: RELATION_DEPLOYED_ON,
      deployment_status: 'deployed',
      external_id: 'abc',
      deployed_at: new Date('2026-10-01T10:00:00.000Z'),
      last_sync_at: '2026-10-02T10:00:00.000Z',
      hit_count: 4,
      validation_status: 'prevented',
    } as unknown as StoreRelation);
    expect(extension).toEqual({
      deployment_status: 'deployed',
      external_id: 'abc',
      deployed_at: '2026-10-01T10:00:00.000Z',
      last_sync_at: '2026-10-02T10:00:00.000Z',
      removed_at: undefined,
      hit_count: 4,
      last_hit_at: undefined,
      validation_status: 'prevented',
      last_validation_at: undefined,
      validation_run_id: undefined,
      error_message: undefined,
    });
  });

  it('should export the reports counted at the last hit, so a synchronized platform does not count their retries', () => {
    const extension = convertDeployedOnToStixExtension({
      relationship_type: RELATION_DEPLOYED_ON,
      deployment_status: 'active',
      hit_count: 3,
      first_hit_at: '2026-10-01T10:00:00.000Z',
      last_hit_at: '2026-10-02T10:00:00.000Z',
      last_hit_report_ids: ['hits-report-1', 'hits-report-2'],
    } as unknown as StoreRelation);
    expect(extension.first_hit_at).toEqual('2026-10-01T10:00:00.000Z');
    expect(extension.last_hit_report_ids).toEqual(['hits-report-1', 'hits-report-2']);
    const none = convertDeployedOnToStixExtension({ relationship_type: RELATION_DEPLOYED_ON, last_hit_report_ids: [] } as unknown as StoreRelation);
    expect(none.last_hit_report_ids).toBeUndefined();
  });

  it('should not add anything to other relationship types', () => {
    expect(convertDeployedOnToStixExtension({ relationship_type: 'uses' } as unknown as StoreRelation)).toEqual({});
  });
});

describe('markings of the relationships generated for a pair', () => {
  it('should carry the markings of the indicator and of the security platform, once each', () => {
    const indicator = { 'object-marking': ['tlp-green', 'pap-amber'] };
    const platform = { 'object-marking': ['tlp-green', 'tlp-red'] };
    expect(pairMarkings(indicator, platform)).toEqual(['tlp-green', 'pap-amber', 'tlp-red']);
    expect(pairMarkings({}, platform)).toEqual(['tlp-green', 'tlp-red']);
    expect(pairMarkings({ 'object-marking': null }, {})).toEqual([]);
  });

  it('should only count the deployments every reader of the indicator can read', () => {
    const indicator = { 'object-marking': ['tlp-green', 'pap-amber'] };
    expect(isReadableWithIndicator({ 'object-marking': ['tlp-green'] }, indicator)).toEqual(true);
    expect(isReadableWithIndicator({}, indicator)).toEqual(true);
    // The platform added a marking the indicator does not carry
    expect(isReadableWithIndicator({ 'object-marking': ['tlp-green', 'tlp-red'] }, indicator)).toEqual(false);
    expect(isReadableWithIndicator({ 'object-marking': ['tlp-green'] }, {})).toEqual(false);
  });

  it('should accept the lower markings of a type the indicator carries a higher one of', () => {
    const ranks = new Map([['tlp-green', { type: 'TLP', order: 2 }], ['tlp-red', { type: 'TLP', order: 4 }], ['pap-red', { type: 'PAP', order: 4 }]]);
    // Readers cleared for TLP:RED are cleared for TLP:GREEN
    expect(isReadableWithIndicator({ 'object-marking': ['tlp-red'] }, { 'object-marking': ['tlp-red'] }, { 'object-marking': ['tlp-green'] }, undefined, ranks)).toEqual(true);
    expect(isReadableWithIndicator({ 'object-marking': ['tlp-red'] }, { 'object-marking': ['tlp-green'] }, { 'object-marking': ['tlp-red'] }, undefined, ranks)).toEqual(false);
    expect(isReadableWithIndicator({}, { 'object-marking': ['tlp-red'] }, { 'object-marking': ['pap-red'] }, undefined, ranks)).toEqual(false);
  });

  it('should not count a deployment shared with fewer organizations or members than the indicator', () => {
    const indicator = { granted: ['org-a', 'org-b'] };
    const sharing = { enforced: true, individualIds: new Set(['individual-1']) };
    expect(isReadableWithIndicator({ granted: ['org-a', 'org-b', 'org-c'] }, indicator, undefined, sharing)).toEqual(true);
    expect(isReadableWithIndicator({ granted: ['org-a'] }, indicator, undefined, sharing)).toEqual(false);
    expect(isReadableWithIndicator({}, indicator, undefined, sharing)).toEqual(false);
    // The security platform is checked like the deployment
    expect(isReadableWithIndicator({ granted: ['org-a', 'org-b'] }, indicator, { granted: ['org-b'] }, sharing)).toEqual(false);
    // Without a platform organization, organizations do not restrict reads
    expect(isReadableWithIndicator({ granted: ['org-a'] }, indicator)).toEqual(true);
    // An indicator shared with no organization is only read by the platform organization, which reads every deployment
    expect(isReadableWithIndicator({ granted: ['org-a'] }, {}, undefined, sharing)).toEqual(true);
    // ... except the users of the individual who created it, who only read what this individual created
    expect(isReadableWithIndicator({ granted: ['org-a'] }, { 'created-by': 'individual-1' }, undefined, sharing)).toEqual(false);
    expect(isReadableWithIndicator({ 'created-by': 'individual-1' }, { 'created-by': 'individual-1' }, { 'created-by': 'individual-1' }, sharing)).toEqual(true);
    expect(isReadableWithIndicator({}, { 'created-by': 'organization-1' }, {}, sharing)).toEqual(true);
    expect(isReadableWithIndicator({ restricted_members: [{ id: 'user-1', access_right: 'view' }] }, {})).toEqual(false);
    // Authorized members of the indicator read it whatever their organization
    expect(isReadableWithIndicator({ granted: ['org-a'] }, { restricted_members: [{ id: 'user-2', access_right: 'view' }] })).toEqual(false);
  });
});
