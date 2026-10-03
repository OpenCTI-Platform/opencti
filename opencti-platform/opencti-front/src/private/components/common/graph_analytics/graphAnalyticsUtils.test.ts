import { describe, expect, it, vi } from 'vitest';
import { collectPathElementIds, formatSimilarityScore, GRAPH_FEATURE_FAMILY_LABELS, isGraphSimilarEntityType, similarityScoreSeverity } from './graphAnalyticsUtils';

vi.mock('../../../../relay/environment', () => ({
  commitMutation: vi.fn(),
  defaultCommitMutation: {},
}));

describe('graphAnalyticsUtils', () => {
  it('formats scores as bounded percentages', () => {
    expect(formatSimilarityScore(0.4567)).toBe('46%');
    expect(formatSimilarityScore(1)).toBe('100%');
    expect(formatSimilarityScore(1.7)).toBe('100%');
    expect(formatSimilarityScore(-0.2)).toBe('0%');
    expect(formatSimilarityScore(null)).toBe('0%');
    expect(formatSimilarityScore(Number.NaN)).toBe('0%');
  });

  it('maps scores to a severity that grows with the similarity', () => {
    expect(similarityScoreSeverity(0.1)).toBe('low');
    expect(similarityScoreSeverity(0.25)).toBe('medium');
    expect(similarityScoreSeverity(0.5)).toBe('high');
    expect(similarityScoreSeverity(0.9)).toBe('critical');
  });

  it('knows which entity types carry a similarity profile', () => {
    expect(isGraphSimilarEntityType('Intrusion-Set')).toBe(true);
    expect(isGraphSimilarEntityType('Domain-Name')).toBe(true);
    expect(isGraphSimilarEntityType('Report')).toBe(true);
    expect(isGraphSimilarEntityType('Attack-Pattern')).toBe(false);
    expect(isGraphSimilarEntityType('StixFile')).toBe(false);
  });

  it('labels every evidence family returned by the platform', () => {
    ['techniques', 'tools', 'malware', 'infrastructure', 'victims', 'certificates', 'asn', 'registrar', 'nameservers', 'hosting', 'reports', 'objects']
      .forEach((family) => expect(GRAPH_FEATURE_FAMILY_LABELS[family]).toBeTruthy());
  });

  it('collects the entities and relationships of paths without duplicates', () => {
    const ids = collectPathElementIds([
      { node_ids: ['a', 'b', 'c'], relationship_ids: ['r1', 'r2'] },
      { node_ids: ['a', 'd', 'c'], relationship_ids: ['r3', 'r4'] },
    ]);
    expect(ids).toEqual(['a', 'b', 'c', 'r1', 'r2', 'd', 'r3', 'r4']);
    expect(collectPathElementIds([])).toEqual([]);
  });
});
