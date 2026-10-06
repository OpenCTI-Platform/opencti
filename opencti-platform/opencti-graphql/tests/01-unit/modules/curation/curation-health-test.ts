import { describe, expect, it } from 'vitest';
import { countExistingSubjects, estimateDuplicates, estimateExistingDuplicates } from '../../../../src/modules/curation/curation-health';

describe('Knowledge Health duplicate estimate', () => {
  it('counts, for each group of entities proposed for a merge, the entities that would disappear', () => {
    expect(estimateDuplicates([['a', 'b'], ['b', 'c'], ['d', 'e']])).toBe(3);
    expect(estimateDuplicates([])).toBe(0);
  });

  it('only counts the subjects that still exist', () => {
    const pairs = [['a', 'b'], ['c', 'd'], ['e', 'f', 'g']];
    // d was deleted and g merged into another entity since their proposals were raised.
    expect(estimateExistingDuplicates(pairs, new Set(['a', 'b', 'c', 'e', 'f']))).toBe(2);
    expect(estimateExistingDuplicates(pairs, new Set())).toBe(0);
  });

  it('never estimates more duplicates than there are existing subjects', () => {
    const existing = new Set(['a', 'b', 'c']);
    expect(estimateExistingDuplicates([['a', 'x'], ['b', 'y'], ['c', 'z'], ['a', 'b']], existing)).toBeLessThan(existing.size);
  });
});

describe('Knowledge Health stale count', () => {
  it('counts each existing stale subject once and ignores the deleted or merged ones', () => {
    // a was found stale twice; b was deleted and c merged into another entity since their proposals were raised.
    expect(countExistingSubjects([['a'], ['a'], ['b'], ['c'], ['d']], new Set(['a', 'd']))).toBe(2);
    expect(countExistingSubjects([['a'], ['b']], new Set())).toBe(0);
    expect(countExistingSubjects([], new Set(['a']))).toBe(0);
  });
});
