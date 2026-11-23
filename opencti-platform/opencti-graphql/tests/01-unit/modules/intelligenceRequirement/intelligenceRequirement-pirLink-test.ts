import { describe, expect, it } from 'vitest';
import { buildRequirementForPir, mirroredRequirementPatch } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-pirLink';
import { legacyCriterionId, legacyGroupId } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-legacy';
import type { BasicStoreEntityPir } from '../../../../src/modules/pir/pir-types';
import { PirType } from '../../../../src/generated/graphql';

const criterion = (target: string) => JSON.stringify({
  mode: 'and',
  filterGroups: [],
  filters: [
    { key: ['entity_type'], values: ['targets'], operator: 'eq', mode: 'or' },
    { key: ['toId'], values: [target], operator: 'eq', mode: 'or' },
  ],
});

const buildPir = (overrides: Partial<BasicStoreEntityPir> = {}) => ({
  id: 'pir-id',
  internal_id: 'pir-id',
  name: 'Europe healthcare',
  description: 'Threats on European hospitals',
  pir_type: PirType.ThreatLandscape,
  pir_rescan_days: 30,
  lastEventId: '1763700000000-0',
  pir_filters: JSON.stringify({ mode: 'and', filterGroups: [], filters: [{ key: ['confidence'], values: ['80'], operator: 'gte', mode: 'or' }] }),
  pir_criteria: [{ filters: criterion('france'), weight: 2 }, { filters: criterion('healthcare'), weight: 1 }],
  restricted_members: [{ id: 'user-admin', access_right: 'admin' }],
  ...overrides,
} as unknown as BasicStoreEntityPir);

describe('Pir to intelligence requirement link', () => {
  it('should build the requirement of a Pir with its scope, weights, window, position and members', () => {
    const pir = buildPir();
    const attributes = buildRequirementForPir(pir);
    expect(attributes.name).toEqual(pir.name);
    expect(attributes.description).toEqual(pir.description);
    expect(attributes.ir_pir_id).toEqual('pir-id');
    expect(attributes.ir_rescan_days).toEqual(30);
    // the stream position of the Pir is kept: no rescan storm when an existing Pir is linked
    expect(attributes.lastEventId).toEqual(pir.lastEventId);
    expect(JSON.parse(attributes.ir_processing)).toEqual({ catchup_from: pir.lastEventId });
    expect(attributes.authorized_members).toEqual(pir.restricted_members);
    const groups = JSON.parse(attributes.ir_subject_groups);
    expect(groups.map((g: { id: string; entity_ids: string[] }) => [g.id, g.entity_ids])).toEqual([[legacyGroupId(0), ['france']], [legacyGroupId(1), ['healthcare']]]);
    const criteria = JSON.parse(attributes.ir_scope_criteria);
    expect(criteria.map((c: { id: string; relationship_types: string[] }) => [c.id, c.relationship_types])).toEqual([[legacyCriterionId(0), ['targets']], [legacyCriterionId(1), ['targets']]]);
    const rules = JSON.parse(attributes.ir_relevance_rules);
    expect(rules.map((r: { points: number }) => r.points)).toEqual([67, 33]);
  });

  it('should build an active requirement: it is the only engine that flags the Pir', () => {
    expect(buildRequirementForPir(buildPir()).ir_status).toEqual('active');
  });

  it('should be deterministic (a migration run twice builds the same requirement)', () => {
    expect(buildRequirementForPir(buildPir())).toEqual(buildRequirementForPir(buildPir()));
  });

  it('should keep no members when the Pir has none', () => {
    expect(buildRequirementForPir(buildPir({ restricted_members: undefined as never })).authorized_members).toEqual([]);
  });

  it('should mirror only the name and the description of a Pir patch', () => {
    expect(mirroredRequirementPatch([{ key: 'name', value: ['New name'] }, { key: 'description', value: ['New description'] }]))
      .toEqual({ name: 'New name', description: 'New description' });
    expect(mirroredRequirementPatch([{ key: 'lastEventId', value: ['1-0'] }])).toEqual({});
    expect(mirroredRequirementPatch([{ key: 'description', value: [] }])).toEqual({ description: '' });
  });
});
