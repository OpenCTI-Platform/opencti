import { describe, expect, it } from 'vitest';
import {
  computeSimilarityScore,
  cosineSimilarity,
  GRAPH_FEATURE_WEIGHTS,
  intersect,
  rankSimilarProfiles,
  STRUCTURAL_SCORE_WEIGHT,
  weightedJaccard,
  weightedSharedCount,
} from '../../../../src/modules/graphAnalytics/graphAnalytics-scoring';
import type { GraphFeatureProfile } from '../../../../src/modules/graphAnalytics/graphAnalytics-types';

const profile = (id: string, features: GraphFeatureProfile['features'], relationVector: Record<string, number> = { uses: 1 }): GraphFeatureProfile => ({
  id,
  entity_type: 'Intrusion-Set',
  kind: 'threat',
  features,
  relation_vector: relationVector,
});

describe('graph analytics scoring', () => {
  it('should intersect without duplicates', () => {
    expect(intersect(['a', 'b', 'b', 'c'], ['b', 'c', 'd'])).toEqual(['b', 'c']);
    expect(intersect([], ['a'])).toEqual([]);
  });

  it('should compute a weighted Jaccard index over families', () => {
    const { value, shared, sharedCount } = weightedJaccard(
      { techniques: ['t1', 't2'], malware: ['m1'] },
      { techniques: ['t2', 't3'], malware: ['m1'] },
    );
    // techniques: 1 * 1 / (1 * 3), malware: 2 * 1 / (2 * 1)
    const expected = (GRAPH_FEATURE_WEIGHTS.techniques * 1 + GRAPH_FEATURE_WEIGHTS.malware * 1)
      / (GRAPH_FEATURE_WEIGHTS.techniques * 3 + GRAPH_FEATURE_WEIGHTS.malware * 1);
    expect(value).toBeCloseTo(expected, 10);
    expect(shared).toEqual({ techniques: ['t2'], malware: ['m1'] });
    expect(sharedCount).toBe(2);
  });

  it('should return 0 when nothing is comparable', () => {
    expect(weightedJaccard({}, {}).value).toBe(0);
    expect(weightedJaccard({ tools: ['a'] }, { victims: ['b'] }).value).toBe(0);
  });

  it('should compute cosine similarity of sparse vectors', () => {
    expect(cosineSimilarity({ uses: 2, targets: 0 }, { uses: 4 })).toBeCloseTo(1, 10);
    expect(cosineSimilarity({ uses: 1 }, { targets: 1 })).toBe(0);
    expect(cosineSimilarity({}, { targets: 1 })).toBe(0);
  });

  it('should never score a pair without shared evidence', () => {
    const result = computeSimilarityScore(profile('a', { tools: ['x'] }), profile('b', { tools: ['y'] }));
    expect(result).toEqual({ score: 0, jaccard: 0, structural: 0, shared: {}, shared_count: 0 });
  });

  it('should combine the Jaccard and structural parts', () => {
    const result = computeSimilarityScore(
      profile('a', { tools: ['x', 'y'] }, { uses: 2 }),
      profile('b', { tools: ['x', 'y'] }, { uses: 5 }),
    );
    expect(result.jaccard).toBe(1);
    expect(result.structural).toBe(1);
    expect(result.score).toBeCloseTo((1 - STRUCTURAL_SCORE_WEIGHT) + STRUCTURAL_SCORE_WEIGHT, 4);
    expect(result.shared).toEqual({ tools: ['x', 'y'] });
  });

  it('should rank candidates deterministically, apply minScore and topN, and skip the source itself', () => {
    const source = profile('s', { techniques: ['t1', 't2', 't3'], tools: ['k1'] });
    const candidates = [
      profile('s', { techniques: ['t1'] }),
      profile('c1', { techniques: ['t1', 't2', 't3'], tools: ['k1'] }),
      profile('c2', { techniques: ['t1'] }),
      profile('c3', { techniques: ['t9'] }),
      profile('c4', { techniques: ['t1', 't2'] }),
    ];
    const ranked = rankSimilarProfiles(source, candidates, 2, 0.1);
    expect(ranked.map((r) => r.target_id)).toEqual(['c1', 'c4']);
    expect(ranked[0].score).toBeGreaterThan(ranked[1].score);
    const all = rankSimilarProfiles(source, candidates, 10, 0);
    expect(all.map((r) => r.target_id)).toEqual(['c1', 'c4', 'c2']);
  });

  it('should weight shared counts by family', () => {
    expect(weightedSharedCount({ malware: 2, victims: 2 })).toBe(GRAPH_FEATURE_WEIGHTS.malware * 2 + GRAPH_FEATURE_WEIGHTS.victims * 2);
  });
});
