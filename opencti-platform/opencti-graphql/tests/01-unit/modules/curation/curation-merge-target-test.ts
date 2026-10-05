import { describe, expect, it } from 'vitest';
import { selectMergeTarget } from '../../../../src/modules/curation/curation-detectors';

describe('Curation merge target', () => {
  it('keeps the entity with the most relationships', () => {
    expect(selectMergeTarget([
      { id: 'clop', relationships: 3, names: 5 },
      { id: 'cl0p', relationships: 12, names: 1 },
    ])).toBe('cl0p');
  });

  it('breaks a relationship tie with the number of names, then with the id', () => {
    expect(selectMergeTarget([
      { id: 'b', relationships: 4, names: 1 },
      { id: 'a', relationships: 4, names: 3 },
    ])).toBe('a');
    expect(selectMergeTarget([
      { id: 'b', relationships: 4, names: 2 },
      { id: 'a', relationships: 4, names: 2 },
    ])).toBe('a');
  });

  it('has no target without candidates', () => {
    expect(selectMergeTarget([])).toBeUndefined();
  });
});
