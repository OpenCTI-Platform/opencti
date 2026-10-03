import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { computeSnapshotRetentionDate } from '../../../../src/manager/snapshotManager';
import { buildAggregatesMessage, buildChangeMessage } from '../../../../src/modules/timeMachine/timeMachine-changeDigest';
import { savedFilterScopeEntityTypes } from '../../../../src/modules/timeMachine/landscapeDiff-domain';
import type { BasicStoreEntityRetentionRule } from '../../../../src/modules/retentionRules/retentionRules-types';
import type { LandscapeDiffAggregates, LandscapeDiffEntitySummary } from '../../../../src/modules/timeMachine/timeMachine-types';

const rule = (input: Partial<BasicStoreEntityRetentionRule>) => ({
  scope: 'history',
  active: true,
  max_retention: 30,
  retention_unit: 'days',
  filters: '',
  ...input,
}) as BasicStoreEntityRetentionRule;

const NOW = '2026-10-01T00:00:00.000Z';

describe('Knowledge snapshot retention', () => {
  it('should keep snapshots when no global history retention applies', () => {
    expect(computeSnapshotRetentionDate([], NOW, 0)).toBeNull();
    expect(computeSnapshotRetentionDate([rule({ scope: 'knowledge' })], NOW, 0)).toBeNull();
    expect(computeSnapshotRetentionDate([rule({ active: false })], NOW, 0)).toBeNull();
    const filtered = JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], values: ['Report'] }], filterGroups: [] });
    expect(computeSnapshotRetentionDate([rule({ filters: filtered })], NOW, 0)).toBeNull();
  });

  it('should align snapshots with the shortest global history retention', () => {
    const date = computeSnapshotRetentionDate([rule({ max_retention: 90 }), rule({ max_retention: 30 })], NOW, 0);
    expect(date).toEqual('2026-09-01T00:00:00.000Z');
    const empty = JSON.stringify({ mode: 'and', filters: [], filterGroups: [] });
    expect(computeSnapshotRetentionDate([rule({ max_retention: 2, retention_unit: 'weeks', filters: empty })], NOW, 0)).toEqual('2026-09-17T00:00:00.000Z');
  });

  it('should apply the configured snapshot retention when it is shorter', () => {
    expect(computeSnapshotRetentionDate([rule({ max_retention: 90 })], NOW, 10)).toEqual('2026-09-21T00:00:00.000Z');
    expect(computeSnapshotRetentionDate([], NOW, 10)).toEqual('2026-09-21T00:00:00.000Z');
  });
});

describe('Change digest messages', () => {
  const summary: LandscapeDiffEntitySummary = {
    entity_id: 'id',
    entity_type: 'Intrusion-Set',
    name: 'APT-TEST',
    created_in_period: false,
    revoked_in_period: false,
    attributes_changed: 2,
    relationships_added: 3,
    relationships_removed: 1,
    relationships_revoked: 0,
    confidence_before: 50,
    confidence_after: 75,
    score_before: null,
    score_after: null,
    change_score: 12,
  };

  it('should summarize the changes of an entity', () => {
    expect(buildChangeMessage(summary)).toEqual('`3` new relationship(s), `1` removed relationship(s), `2` attribute(s) changed, confidence `50` -> `75`');
    expect(buildChangeMessage({ ...summary, created_in_period: true, relationships_added: 0, relationships_removed: 0, attributes_changed: 0, confidence_before: null }))
      .toEqual('created');
  });

  it('should summarize the landscape aggregates', () => {
    const aggregates = {
      entities_in_scope: 10,
      entities_changed: 4,
      new_relationships: 12,
      removed_relationships: 2,
      revocations: 1,
      new_techniques: [{ id: 't', entity_type: 'Attack-Pattern', name: 'T1059', count: 2 }],
      new_malware: [],
      new_tools: [],
      new_infrastructure_count: 3,
    } as unknown as LandscapeDiffAggregates;
    expect(buildAggregatesMessage(aggregates))
      .toEqual('`4` of `10` entities changed, `12` new relationship(s), `2` removed, `1` revocation(s), `1` new technique(s), `3` new infrastructure');
  });
});

describe('Landscape diff scopes', () => {
  it('should map saved filter list scopes to entity types', () => {
    expect(savedFilterScopeEntityTypes('intrusionSets')).toEqual(['Intrusion-Set']);
    expect(savedFilterScopeEntityTypes('malwares')).toEqual(['Malware']);
    expect(savedFilterScopeEntityTypes('unknown-list')).toBeNull();
    expect(savedFilterScopeEntityTypes(undefined)).toBeNull();
  });
});
