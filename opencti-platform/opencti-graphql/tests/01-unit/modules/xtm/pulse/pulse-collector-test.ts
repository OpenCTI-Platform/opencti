import { describe, expect, it, vi } from 'vitest';

const MARKINGS = vi.hoisted(() => [
  { internal_id: 'marking-clear', standard_id: 'marking-definition--clear', definition_type: 'TLP', definition: 'TLP:CLEAR' },
  { internal_id: 'marking-amber', standard_id: 'marking-definition--amber', definition_type: 'TLP', definition: 'TLP:AMBER' },
  { internal_id: 'marking-amber-strict', standard_id: 'marking-definition--amber-strict', definition_type: 'TLP', definition: 'TLP:AMBER+STRICT' },
  { internal_id: 'marking-red', standard_id: 'marking-definition--red', definition_type: 'TLP', definition: 'TLP:RED' },
  { internal_id: 'marking-pap-red', standard_id: 'marking-definition--pap-red', definition_type: 'PAP', definition: 'PAP:RED' },
  { internal_id: 'marking-internal', standard_id: 'marking-definition--internal', definition_type: 'statement', definition: 'INTERNAL ONLY' },
]);

vi.mock('../../../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn(async () => MARKINGS),
  getEntityFromCache: vi.fn(),
}));

import { aggregatePulseActivity, assertPulseBatch, buildPulseBatches, mergePulseActivity, type PulseActivity } from '../../../../../src/modules/xtm/pulse/pulse-collector';
import { buildPulseMarkingPolicy, isPulseContributable } from '../../../../../src/modules/xtm/pulse/pulse-settings';
import { computeStableKeys } from '../../../../../src/modules/xtm/pulse/pulse-hashing';
import { PULSE_SCOPE_ENTITY_TYPES, type BasicStorePulseEntity, type PulseBatch, type PulseSettingsValues } from '../../../../../src/modules/xtm/pulse/pulse-types';
import { PulseMode, PulseRegionBucket, PulseSectorBucket } from '../../../../../src/generated/graphql';
import { executionContext } from '../../../../../src/utils/access';

const testContext = executionContext('pulse-collector-test');

const SALT = '00112233445566778899aabbccddeeff';
const BUCKETS = { sector_bucket: PulseSectorBucket.Finance, region_bucket: PulseRegionBucket.Europe };

const settings = (overrides: Partial<PulseSettingsValues> = {}): PulseSettingsValues => ({
  mode: PulseMode.ContributeAndRead,
  scopes: PULSE_SCOPE_ENTITY_TYPES,
  excludedMarkingIds: ['marking-internal'],
  sectorBucket: PulseSectorBucket.Finance,
  regionBucket: PulseRegionBucket.Europe,
  consentVersion: '2026-10-1',
  consentDate: new Date(),
  consentUserId: 'user-id',
  ...overrides,
});

const entity = (id: string, data: Partial<BasicStorePulseEntity> & Record<string, unknown>): BasicStorePulseEntity => ({
  internal_id: id,
  id,
  standard_id: `indicator--${id}`,
  _index: 'opencti_stix_domain_objects-000001',
  ...data,
} as unknown as BasicStorePulseEntity);

const SHAREABLE = entity('shareable-indicator', { entity_type: 'Indicator', pattern: "[ipv4-addr:value = '203.0.113.66']", pattern_type: 'stix', 'object-marking': ['marking-clear'] });
const AMBER = entity('amber-domain', { entity_type: 'Indicator', pattern: "[domain-name:value = 'amber-share.example.org']", pattern_type: 'stix', 'object-marking': ['marking-amber'] });
const RED = entity('red-indicator', { entity_type: 'Indicator', pattern: "[domain-name:value = 'red-secret.example.net']", pattern_type: 'stix', 'object-marking': ['marking-red'] });
const AMBER_STRICT = entity('amber-strict-malware', { entity_type: 'Malware', name: 'StrictlyInternalLoader', aliases: ['SIL'], 'object-marking': ['marking-amber-strict'] });
const PAP_RED = entity('pap-red-vulnerability', { entity_type: 'Vulnerability', name: 'CVE-2031-0001', 'object-marking': ['marking-pap-red'] });
const ADMIN_EXCLUDED = entity('internal-tool', { entity_type: 'Tool', name: 'HouseMadeTool', 'object-marking': ['marking-internal'] });
const UNKNOWN_MARKING = entity('unknown-marking', { entity_type: 'Attack-Pattern', x_mitre_id: 'T9999', 'object-marking': ['marking-that-does-not-exist'] });
const RESTRICTED = entity('restricted-intrusion-set', { entity_type: 'Intrusion-Set', name: 'Restricted Bear', restricted_members: [{ id: 'user', access_right: 'admin' }] });
const SHARED_TO_ORGANIZATION = entity('granted-malware', { entity_type: 'Malware', name: 'OrgOnlyRat', granted: ['organization-id'] });
const OUT_OF_SCOPE = entity('report', { entity_type: 'Report', name: 'Quarterly threat report' });
const THREAT = entity('lockbit', { entity_type: 'Intrusion-Set', name: 'LockBit Gang', aliases: ['LockBit 3.0'], 'object-marking': [] });

const ALL_ENTITIES = [SHAREABLE, AMBER, RED, AMBER_STRICT, PAP_RED, ADMIN_EXCLUDED, UNKNOWN_MARKING, RESTRICTED, SHARED_TO_ORGANIZATION, OUT_OF_SCOPE, THREAT];
const EXCLUDED_ENTITIES = [RED, AMBER_STRICT, PAP_RED, ADMIN_EXCLUDED, UNKNOWN_MARKING, RESTRICTED, SHARED_TO_ORGANIZATION, OUT_OF_SCOPE];

const activityFor = (entities: BasicStorePulseEntity[]): PulseActivity => {
  const activity: PulseActivity = new Map();
  entities.forEach((item) => activity.set(item.internal_id, new Map([['created', 1], ['sighted', 3]])));
  return activity;
};

// Every raw value an excluded or included object holds: none of them may appear in what leaves the platform.
const RAW_VALUES = [
  '203.0.113.66', 'amber-share.example.org', 'red-secret.example.net', 'StrictlyInternalLoader', 'SIL', 'CVE-2031-0001', 'HouseMadeTool',
  'T9999', 'Restricted Bear', 'OrgOnlyRat', 'Quarterly threat report', 'LockBit', 'lockbit', 'Gang',
  ...ALL_ENTITIES.flatMap((item) => [item.internal_id, item.standard_id]),
];

describe('Threat Pulse collector privacy guardrails', () => {
  it('should always exclude TLP:RED, TLP:AMBER+STRICT and PAP:RED, whatever the configuration', async () => {
    const policy = await buildPulseMarkingPolicy(testContext, settings({ excludedMarkingIds: [] }));
    expect(policy.excludedMarkingIds).toEqual(new Set(['marking-amber-strict', 'marking-red', 'marking-pap-red']));
    expect(isPulseContributable(RED, policy, PULSE_SCOPE_ENTITY_TYPES)).toBe(false);
    expect(isPulseContributable(AMBER_STRICT, policy, PULSE_SCOPE_ENTITY_TYPES)).toBe(false);
    expect(isPulseContributable(PAP_RED, policy, PULSE_SCOPE_ENTITY_TYPES)).toBe(false);
    expect(isPulseContributable(AMBER, policy, PULSE_SCOPE_ENTITY_TYPES)).toBe(true);
  });

  it('should never produce a record for an excluded object', async () => {
    const policy = await buildPulseMarkingPolicy(testContext, settings());
    const aggregation = aggregatePulseActivity(activityFor(ALL_ENTITIES), ALL_ENTITIES, policy, PULSE_SCOPE_ENTITY_TYPES);
    const excludedKeys = EXCLUDED_ENTITIES.flatMap((item) => computeStableKeys(item));
    const recordKeys = aggregation.records.map((record) => record.key);
    excludedKeys.forEach((key) => expect(recordKeys).not.toContain(key));
    expect(aggregation.contributedEntities.map((item) => item.internal_id).sort()).toEqual([AMBER.internal_id, SHAREABLE.internal_id, THREAT.internal_id].sort());
    expect(aggregation.excludedCount).toBe(EXCLUDED_ENTITIES.length);
  });

  it('should respect the configured scopes', async () => {
    const policy = await buildPulseMarkingPolicy(testContext, settings({ scopes: ['Intrusion-Set'] }));
    const aggregation = aggregatePulseActivity(activityFor(ALL_ENTITIES), ALL_ENTITIES, policy, ['Intrusion-Set']);
    expect(aggregation.contributedEntities.map((item) => item.internal_id)).toEqual([THREAT.internal_id]);
  });

  it('should only serialize the batch header and hash/count tuples, never a raw value or a stable key', async () => {
    const policy = await buildPulseMarkingPolicy(testContext, settings());
    const aggregation = aggregatePulseActivity(activityFor(ALL_ENTITIES), ALL_ENTITIES, policy, PULSE_SCOPE_ENTITY_TYPES);
    const batches = buildPulseBatches(aggregation.records, SALT, '2026-10-03', BUCKETS);
    expect(batches).toHaveLength(1);
    const serialized = JSON.stringify(batches);
    RAW_VALUES.forEach((value) => expect(serialized.toLowerCase()).not.toContain(value.toLowerCase()));
    aggregation.records.forEach((record) => expect(serialized).not.toContain(record.key));
    batches.forEach((batch) => {
      expect(Object.keys(batch).sort()).toEqual(['day', 'records', 'region_bucket', 'sector_bucket']);
      batch.records.forEach((record) => {
        expect(Object.keys(record).sort()).toEqual(['count', 'event_kind', 'hash', 'object_type']);
        expect(record.hash).toMatch(/^[0-9a-f]{32}$/);
      });
    });
  });

  it('should aggregate the counts of a key per event kind', async () => {
    const policy = await buildPulseMarkingPolicy(testContext, settings());
    const activity = activityFor([SHAREABLE]);
    mergePulseActivity(activity, [{ entityId: SHAREABLE.internal_id, eventKind: 'hunted', count: 2 }, { entityId: SHAREABLE.internal_id, eventKind: 'sighted', count: 4 }]);
    const aggregation = aggregatePulseActivity(activity, [SHAREABLE], policy, PULSE_SCOPE_ENTITY_TYPES);
    const counts = Object.fromEntries(aggregation.records.map((record) => [record.event_kind, record.count]));
    expect(counts).toEqual({ created: 1, sighted: 7, hunted: 2 });
  });

  it('should split the records in batches of 5000', () => {
    const records = Array.from({ length: 12001 }, (_, index) => ({
      key: index.toString(16).padStart(32, '0'),
      object_type: 'indicator' as const,
      event_kind: 'created' as const,
      count: 1,
    }));
    const batches = buildPulseBatches(records, SALT, '2026-10-03', BUCKETS);
    expect(batches.map((batch) => batch.records.length)).toEqual([5000, 5000, 2001]);
  });
});

describe('Threat Pulse outbound payload schema', () => {
  const validBatch = (): PulseBatch => ({
    day: '2026-10-03',
    sector_bucket: PulseSectorBucket.Finance,
    region_bucket: PulseRegionBucket.Europe,
    records: [{ hash: '0123456789abcdef0123456789abcdef', object_type: 'indicator', event_kind: 'created', count: 2 }],
  });

  it('should accept the contract shape', () => {
    expect(() => assertPulseBatch(validBatch())).not.toThrow();
  });

  it.each([
    ['a value field on a record', (batch: any) => {
      batch.records[0].value = '203.0.113.66';
    }],
    ['a name field on a record', (batch: any) => {
      batch.records[0].name = 'APT28';
    }],
    ['an organization field on the batch', (batch: any) => {
      batch.organization = 'ACME Bank';
    }],
    ['a platform identifier on the batch', (batch: any) => {
      batch.platform_id = 'abc';
    }],
    ['a non hexadecimal hash', (batch: any) => {
      batch.records[0].hash = 'apt28-not-a-hash-0000000000000000';
    }],
    ['an unknown object type', (batch: any) => {
      batch.records[0].object_type = 'report';
    }],
    ['an unknown event kind', (batch: any) => {
      batch.records[0].event_kind = 'shared';
    }],
    ['a zero count', (batch: any) => {
      batch.records[0].count = 0;
    }],
    ['an excessive count', (batch: any) => {
      batch.records[0].count = 100001;
    }],
    ['a duplicated record', (batch: any) => {
      batch.records.push({ ...batch.records[0] });
    }],
    ['an empty batch', (batch: any) => {
      batch.records = [];
    }],
    ['a fine grained bucket', (batch: any) => {
      batch.sector_bucket = 'acme-bank';
    }],
    ['a malformed day', (batch: any) => {
      batch.day = '03/10/2026';
    }],
  ])('should refuse %s', (_, mutate) => {
    const batch = validBatch();
    mutate(batch);
    expect(() => assertPulseBatch(batch)).toThrow(/Threat Pulse batch refused/);
  });
});
