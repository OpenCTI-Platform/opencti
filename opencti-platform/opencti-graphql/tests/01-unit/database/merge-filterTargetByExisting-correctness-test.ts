import { describe, expect, it, vi } from 'vitest';
import { filterTargetByExisting } from '../../../src/database/middleware';
import { RELATION_RELATED_TO } from '../../../src/schema/stixCoreRelationship';
import { testContext } from '../../utils/testQuery';

// filterTargetByExisting delegates marking deduplication to cleanMarkings (an ES-cache-backed function,
// unrelated to the fix under test). None of the scenarios below use RELATION_OBJECT_MARKING relations,
// so mocking it out keeps these correctness tests fast and dependency-free without changing behavior.
vi.mock('../../../src/utils/markingDefinition-utils', () => ({
  cleanMarkings: vi.fn().mockResolvedValue([]),
}));

const ATTACK_PATTERN = 'Attack-Pattern';
const targetEntity = { internal_id: 'target-entity', entity_type: ATTACK_PATTERN } as any;

// Builds a minimal MergeEntityDependency-shaped object. `dated` controls whether noDate(i_relation) is true or false.
const dep = (internalId: string, entityType: string, dated = false) => ({
  _index: 'test_index',
  internal_id: internalId,
  entity_type: entityType,
  name: `entity-${internalId}`,
  i_relation: {
    internal_id: `rel-${internalId}-${entityType}`,
    entity_type: entityType,
    fromId: 'some-from-id',
    fromType: ATTACK_PATTERN,
    toId: internalId,
    toType: ATTACK_PATTERN,
    ...(dated ? { start_time: '2020-01-01T00:00:00.000Z' } : {}),
  },
});

const filter = (sources: any[], targets: any[]) => filterTargetByExisting(
  testContext,
  targetEntity,
  'from',
  { i_relations_from: sources, i_relations_to: [] } as any,
  { i_relations_from: targets, i_relations_to: [] } as any,
);

describe('filterTargetByExisting correctness', () => {
  it('should return all sources when targets is empty (no possible match)', async () => {
    const sources = [dep('a', RELATION_RELATED_TO), dep('b', RELATION_RELATED_TO)];
    const { redirects } = await filter(sources, []);
    expect(redirects.map((r) => r.internal_id).sort()).toEqual(['a', 'b']);
  });

  it('should return no redirects when sources is empty', async () => {
    const targets = [dep('a', RELATION_RELATED_TO)];
    const { redirects } = await filter([], targets);
    expect(redirects).toEqual([]);
  });

  it('should filter out a source relation that already exists on target with the same type/id and no dates', async () => {
    const sources = [dep('a', RELATION_RELATED_TO)];
    const targets = [dep('a', RELATION_RELATED_TO)]; // same internal_id + entity_type, undated => existing match
    const { redirects } = await filter(sources, targets);
    expect(redirects).toEqual([]);
  });

  it('should keep a source relation when the matching target relation is dated (noDate is false)', async () => {
    const sources = [dep('a', RELATION_RELATED_TO)];
    const targets = [dep('a', RELATION_RELATED_TO, true)]; // same key, but dated => does not count as "already existing"
    const { redirects } = await filter(sources, targets);
    expect(redirects.map((r) => r.internal_id)).toEqual(['a']);
  });

  it('should keep a source relation when internal_id differs from all targets', async () => {
    const sources = [dep('a', RELATION_RELATED_TO)];
    const targets = [dep('b', RELATION_RELATED_TO)];
    const { redirects } = await filter(sources, targets);
    expect(redirects.map((r) => r.internal_id)).toEqual(['a']);
  });

  it('should keep a source relation when entity_type differs from all targets, even with same internal_id', async () => {
    const sources = [dep('a', RELATION_RELATED_TO)];
    const targets = [dep('a', 'targets')]; // different relation type, same internal_id
    const { redirects } = await filter(sources, targets);
    expect(redirects.map((r) => r.internal_id)).toEqual(['a']);
  });

  it('should dedupe two identical source relations (same type+id) into a single redirect', async () => {
    const sources = [dep('a', RELATION_RELATED_TO), dep('a', RELATION_RELATED_TO)];
    const { redirects } = await filter(sources, []);
    expect(redirects.length).toEqual(1);
    expect(redirects[0].internal_id).toEqual('a');
  });

  it('should match when the target bucket has multiple entries sharing the same key, one of which is undated', async () => {
    // Same (type, id) key appearing twice on target side: one dated (doesn't count), one undated (counts).
    const sources = [dep('a', RELATION_RELATED_TO)];
    const targets = [dep('a', RELATION_RELATED_TO, true), dep('a', RELATION_RELATED_TO, false)];
    const { redirects } = await filter(sources, targets);
    expect(redirects).toEqual([]); // the undated entry in the bucket should still produce a match
  });

  it('should keep a source relation when the target bucket only has dated entries under the same key', async () => {
    const sources = [dep('a', RELATION_RELATED_TO)];
    const targets = [dep('a', RELATION_RELATED_TO, true), dep('a', RELATION_RELATED_TO, true)];
    const { redirects } = await filter(sources, targets);
    expect(redirects.map((r) => r.internal_id)).toEqual(['a']);
  });

  it('should handle a realistic mixed batch: some overlapping, some new, some duplicated', async () => {
    const sources = [
      dep('a', RELATION_RELATED_TO), // overlaps with target -> filtered
      dep('b', RELATION_RELATED_TO), // new -> kept
      dep('b', RELATION_RELATED_TO), // duplicate of previous source -> deduped
      dep('c', RELATION_RELATED_TO, true), // new, dated -> kept (dates never disqualify a source itself)
    ];
    const targets = [dep('a', RELATION_RELATED_TO)];
    const { redirects } = await filter(sources, targets);
    expect(redirects.map((r) => r.internal_id).sort()).toEqual(['b', 'c']);
  });

  describe('adversarial hyphen-boundary cases (nested Map index, no string-key collision)', () => {
    it('does NOT falsely match a source (entity_type="a", internal_id="b-c") against a target (entity_type="a-b", internal_id="c")', async () => {
      // A naive `${entity_type}-${internal_id}` string key would collide here (both produce "a-b-c"),
      // since both fields can contain hyphens. The index is nested (entity_type -> internal_id -> deps)
      // specifically to make this kind of pair structurally unable to collide, regardless of hyphen placement.
      const source = dep('b-c', 'a');
      const target = dep('c', 'a-b');
      const { redirects } = await filter([source], [target]);
      expect(redirects.map((r) => r.internal_id)).toEqual(['b-c']); // kept: genuinely distinct pairs, no false match
    });

    it('does not collide when entity_type/internal_id pairs are genuinely distinct', async () => {
      const source = dep('b-c', 'a');
      const target = dep('other', 'a-b');
      const { redirects } = await filter([source], [target]);
      expect(redirects.map((r) => r.internal_id)).toEqual(['b-c']);
    });
  });

  it('should remain correct with a large bucket of same-key target relations (stress, mixed dated/undated)', async () => {
    const sources = [dep('a', RELATION_RELATED_TO)];
    const targets = Array.from({ length: 500 }).map((_, i) => dep('a', RELATION_RELATED_TO, i !== 250)); // one undated entry among 500
    const { redirects } = await filter(sources, targets);
    expect(redirects).toEqual([]); // the single undated entry at index 250 should still be found
  });
});
