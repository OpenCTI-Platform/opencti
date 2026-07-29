import { describe, it, expect } from 'vitest';
import { buildAverageCoverageMap, dedupeCoveredEntities, type CoveredEntityLike } from './securityCoverageAggregation';

const entities: CoveredEntityLike[] = [
  {
    relationship_id: 'rel-1',
    coverage_information: [
      { coverage_name: 'Prevention', coverage_score: 40 },
      { coverage_name: 'Detection', coverage_score: 90 },
    ],
    to: { id: 'ap-1', name: 'AP One' },
  },
  {
    relationship_id: 'rel-2',
    coverage_information: [
      { coverage_name: 'Prevention', coverage_score: 61 },
    ],
    to: { id: 'ap-1', name: 'AP One' },
  },
  {
    relationship_id: 'rel-3',
    coverage_information: [
      { coverage_name: 'Detection', coverage_score: 20 },
    ],
    to: { id: 'ap-2', name: 'AP Two' },
  },
];

describe('securityCoverageAggregation', () => {
  describe('buildAverageCoverageMap', () => {
    it('should average scores per coverage_name grouped by entity id', () => {
      const map = buildAverageCoverageMap(entities);
      expect(map.size).toBe(2);
      const apOne = map.get('ap-1') ?? [];
      // Prevention: (40 + 61) / 2 = 50.5 -> 51 (Math.round)
      expect(apOne.find((c) => c.coverage_name === 'Prevention')?.coverage_score).toBe(51);
      // Detection only present once for ap-1
      expect(apOne.find((c) => c.coverage_name === 'Detection')?.coverage_score).toBe(90);
      const apTwo = map.get('ap-2') ?? [];
      expect(apTwo).toEqual([{ coverage_name: 'Detection', coverage_score: 20 }]);
    });

    it('should ignore entities without a target id', () => {
      const map = buildAverageCoverageMap([
        { relationship_id: 'rel-x', coverage_information: [{ coverage_name: 'Prevention', coverage_score: 10 }], to: null },
      ]);
      expect(map.size).toBe(0);
    });
  });

  describe('dedupeCoveredEntities', () => {
    it('should keep one row per entity using the first relationship id and averaged coverage', () => {
      const deduped = dedupeCoveredEntities(entities);
      expect(deduped).toHaveLength(2);
      const apOne = deduped.find((e) => e.to?.id === 'ap-1');
      expect(apOne?.relationship_id).toBe('rel-1');
      expect(apOne?.coverage_information).toEqual(
        expect.arrayContaining([
          { coverage_name: 'Prevention', coverage_score: 51 },
          { coverage_name: 'Detection', coverage_score: 90 },
        ]),
      );
      const apTwo = deduped.find((e) => e.to?.id === 'ap-2');
      expect(apTwo?.relationship_id).toBe('rel-3');
    });

    it('should preserve first-seen ordering', () => {
      const deduped = dedupeCoveredEntities(entities);
      expect(deduped.map((e) => e.to?.id)).toEqual(['ap-1', 'ap-2']);
    });
  });
});
