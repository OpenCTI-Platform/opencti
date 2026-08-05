import { describe, expect, it, vi } from 'vitest';
import { filterTargetByExisting } from '../../../src/database/middleware';
import { RELATION_RELATED_TO } from '../../../src/schema/stixCoreRelationship';
import { testContext } from '../../utils/testQuery';

// No marking-typed relations are used in the synthetic dataset below, so cleanMarkings is
// mocked out to avoid needing a live cache/Elasticsearch/Redis for this pure algorithmic benchmark.
vi.mock('../../../src/utils/markingDefinition-utils', () => ({
  cleanMarkings: vi.fn().mockResolvedValue([]),
}));

const ATTACK_PATTERN = 'Attack-Pattern';

// Build a synthetic "MergeEntityDependency" list, all disjoint from the target list (worst case:
// filterTargetByExisting must scan through all targets for every source before concluding "no match").
const buildDependencies = (count: number, idPrefix: string) => {
  return Array.from({ length: count }).map((_, index) => ({
    _index: 'test_index',
    internal_id: `${idPrefix}-${index}`,
    entity_type: ATTACK_PATTERN,
    name: `related-entity-${idPrefix}-${index}`,
    i_relation: {
      internal_id: `${idPrefix}-rel-${index}`,
      entity_type: RELATION_RELATED_TO,
      fromId: `source-entity-${index}`,
      fromType: ATTACK_PATTERN,
      toId: `${idPrefix}-${index}`,
      toType: ATTACK_PATTERN,
    },
  }));
};

const targetEntity = { internal_id: 'target-entity', entity_type: ATTACK_PATTERN } as any;

describe('middleware filterTargetByExisting merge algorithm complexity', () => {
  it('should scale near-linearly (O(n+m)) instead of quadratically (O(n x m)) as relation counts grow', async () => {
    // Sizes roughly mirror what was observed in production for a high-relationship-count entity (~78k relations).
    const sizes = [2000, 8000, 32000];
    const timingsMs: number[] = [];

    for (let i = 0; i < sizes.length; i += 1) {
      const size = sizes[i];
      const sourcesDependencies = {
        i_relations_from: buildDependencies(size, 'source'),
        i_relations_to: [],
      } as any;
      // Target relations disjoint from sources so every source hits the "no match" path (worst case for the old O(n x m) scan).
      const targetDependencies = {
        i_relations_from: buildDependencies(size / 4, 'target'),
        i_relations_to: [],
      } as any;

      const start = performance.now();
      const { redirects } = await filterTargetByExisting(
        testContext,
        targetEntity,
        'from',
        sourcesDependencies,
        targetDependencies,
      );
      const elapsed = performance.now() - start;
      timingsMs.push(elapsed);

      expect(redirects.length).toEqual(size);
    }

    // oxlint-disable-next-line no-console
    console.log(
      '[BENCHMARK] filterTargetByExisting timings (ms) for sizes',
      sizes,
      '=>',
      timingsMs,
    );

    // With an O(n x m) algorithm, quadrupling n (2000 -> 8000 -> 32000) would multiply the runtime by ~16x at each step.
    // With the O(n+m) fix, runtime should grow roughly linearly with n (a few x, not ~16x).
    const growthFactor1 = timingsMs[1] / Math.max(timingsMs[0], 1);
    const growthFactor2 = timingsMs[2] / Math.max(timingsMs[1], 1);

    // oxlint-disable-next-line no-console
    console.log(
      '[BENCHMARK] growth factors (should be well under 16x if the fix is effective):',
      growthFactor1,
      growthFactor2,
    );

    expect(growthFactor1).toBeLessThan(10);
    expect(growthFactor2).toBeLessThan(10);
  });

  it('should complete a 78k-relation merge filter (production-scale) in well under a second', async () => {
    const size = 78000;
    const sourcesDependencies = {
      i_relations_from: buildDependencies(size, 'source'),
      i_relations_to: [],
    } as any;
    const targetDependencies = {
      i_relations_from: buildDependencies(5000, 'target'),
      i_relations_to: [],
    } as any;

    const start = performance.now();
    const { redirects } = await filterTargetByExisting(
      testContext,
      targetEntity,
      'from',
      sourcesDependencies,
      targetDependencies,
    );
    const elapsed = performance.now() - start;

    // oxlint-disable-next-line no-console
    console.log(
      `[BENCHMARK] 78k-relation filterTargetByExisting completed in ${elapsed.toFixed(2)}ms`,
    );

    expect(redirects.length).toEqual(size);
    // Previously this kind of volume was observed to hang for hours (O(n x m) with n=78k, m in the thousands).
    // The indexed (O(n+m)) implementation should comfortably finish in well under a second.
    expect(elapsed).toBeLessThan(2000);
  });
});
