import { describe, expect, it } from 'vitest';
import { resolveVocabularyLabels } from '../../../src/database/middleware';
import { testContext } from '../../utils/testQuery';

describe('Time series breakdown vocabulary labels', () => {
  it('should find the name of the vocabularies from the indexed form of their values', async () => {
    // Values as a terms aggregation returns them: lowercase and without accents
    const labels = await resolveVocabularyLabels(testContext, ['reliability_ov', 'case_priority_ov'], ['a - completely reliable', 'p1', 'not-a-vocabulary']);
    expect(labels.get('a - completely reliable')).toEqual('A - Completely reliable');
    expect(labels.get('p1')).toEqual('P1');
    expect(labels.has('not-a-vocabulary')).toBe(false);
  });

  it('should only read the vocabularies of the categories of the field', async () => {
    // P1 exists, but in the priorities of the cases only
    const labels = await resolveVocabularyLabels(testContext, ['reliability_ov'], ['p1']);
    expect(labels.size).toEqual(0);
  });
});
