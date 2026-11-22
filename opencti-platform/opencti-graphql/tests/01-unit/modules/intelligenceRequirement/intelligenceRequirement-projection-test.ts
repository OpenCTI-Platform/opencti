import { describe, expect, it } from 'vitest';
import { matchToPirExplanations, matchToPirScore } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-projection';
import { legacyCriterionId } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-legacy';
import { isPirDrivenByRequirement, PIR_ENGINE_LEGACY, PIR_ENGINE_REQUIREMENT } from '../../../../src/modules/pir/pir-types';
import type { BasicStoreEntityIntelligenceRequirementMatch } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirementMatch-types';

const pir = {
  pir_criteria: [
    { filters: '{"mode":"and","filters":[{"key":["toId"],"values":["france"]}],"filterGroups":[]}', weight: 2 },
    { filters: '{"mode":"and","filters":[{"key":["toId"],"values":["healthcare"]}],"filterGroups":[]}', weight: 1 },
  ],
};

const buildMatch = (criteriaIds: string[], explanations: any[]) => ({
  match_criteria_ids: criteriaIds,
  match_explanations: JSON.stringify(explanations),
} as unknown as BasicStoreEntityIntelligenceRequirementMatch);

describe('intelligence requirement projection onto its Pir', () => {
  it('should tell which engine drives a Pir', () => {
    expect(isPirDrivenByRequirement({})).toBe(false);
    expect(isPirDrivenByRequirement({ pir_engine: null })).toBe(false);
    expect(isPirDrivenByRequirement({ pir_engine: PIR_ENGINE_LEGACY })).toBe(false);
    expect(isPirDrivenByRequirement({ pir_engine: PIR_ENGINE_REQUIREMENT })).toBe(true);
  });

  it('should keep the legacy score formula', () => {
    expect(matchToPirScore(pir, buildMatch([legacyCriterionId(0)], []))).toEqual(67);
    expect(matchToPirScore(pir, buildMatch([legacyCriterionId(1)], []))).toEqual(33);
    expect(matchToPirScore(pir, buildMatch([legacyCriterionId(0), legacyCriterionId(1)], []))).toEqual(100);
    expect(matchToPirScore(pir, buildMatch(['other-criterion'], []))).toEqual(0);
    expect(matchToPirScore({ pir_criteria: [] }, buildMatch([legacyCriterionId(0)], []))).toEqual(0);
  });

  it('should write one legacy explanation per criterion with its relationships', () => {
    const match = buildMatch([legacyCriterionId(0), legacyCriterionId(1)], [
      { criterion_id: legacyCriterionId(1), kind: 'graph', at: '2026-11-22', relationship_id: 'rel-b', anchor_id: 'healthcare' },
      { criterion_id: legacyCriterionId(0), kind: 'graph', at: '2026-11-22', relationship_id: 'rel-a', anchor_id: 'france' },
      { criterion_id: legacyCriterionId(0), kind: 'graph', at: '2026-11-22', relationship_id: 'rel-c', anchor_id: 'france' },
      { criterion_id: legacyCriterionId(0), kind: 'graph', at: '2026-11-22', relationship_id: 'rel-a', anchor_id: 'france' },
      { criterion_id: 'not-legacy', kind: 'keywords', at: '2026-11-22', keyword: 'nginx' },
    ]);
    const explanations = matchToPirExplanations(pir, match);
    expect(explanations.length).toEqual(2);
    expect(explanations[0].criterion).toEqual(pir.pir_criteria[0]);
    expect(explanations[0].dependencies.map((d) => d.element_id)).toEqual(['rel-a', 'rel-c']);
    expect(explanations[1].criterion).toEqual(pir.pir_criteria[1]);
    expect(explanations[1].dependencies.map((d) => d.element_id)).toEqual(['rel-b']);
  });

  it('should fall back on the anchor when a proof has no relationship and ignore bad explanations', () => {
    const match = buildMatch([legacyCriterionId(0)], [
      { criterion_id: legacyCriterionId(0), kind: 'attribute', at: '2026-11-22', anchor_id: 'france' },
      { criterion_id: legacyCriterionId(5), kind: 'graph', at: '2026-11-22', relationship_id: 'rel-x' },
    ]);
    const explanations = matchToPirExplanations(pir, match);
    expect(explanations.length).toEqual(1);
    expect(explanations[0].dependencies).toEqual([{ element_id: 'france', author_id: null }]);
    const broken = { match_criteria_ids: [], match_explanations: 'not json' } as unknown as BasicStoreEntityIntelligenceRequirementMatch;
    expect(matchToPirExplanations(pir, broken)).toEqual([]);
  });
});
