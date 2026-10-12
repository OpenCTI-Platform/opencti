import { describe, expect, it } from 'vitest';
import { findDuplicateResultField } from './SecurityCoverageResultForm-utils';

const existingResults = [
  { name: 'Result of my coverage', external_uri: null },
  { name: 'Linked result', external_uri: 'https://openaev.io/simulations/1' },
];

describe('findDuplicateResultField', () => {
  it('should detect a duplicate name when no external link is given', () => {
    expect(findDuplicateResultField({ name: 'Result of my coverage', externalUri: '' }, existingResults)).toBe('name');
  });

  it('should compare names like the backend (case and surrounding spaces ignored)', () => {
    expect(findDuplicateResultField({ name: '  RESULT of My Coverage ', externalUri: '' }, existingResults)).toBe('name');
  });

  it('should not flag a name used by a result identified by its external link', () => {
    expect(findDuplicateResultField({ name: 'Linked result', externalUri: '' }, existingResults)).toBeNull();
  });

  it('should detect a duplicate external link', () => {
    expect(findDuplicateResultField({ name: 'Other name', externalUri: 'https://openaev.io/simulations/1' }, existingResults)).toBe('externalUri');
  });

  it('should compare external links as is (case sensitive)', () => {
    expect(findDuplicateResultField({ name: 'Other name', externalUri: 'https://openaev.io/Simulations/1' }, existingResults)).toBeNull();
  });

  it('should not flag a known name when a new external link is given', () => {
    expect(findDuplicateResultField({ name: 'Result of my coverage', externalUri: 'https://openaev.io/simulations/2' }, existingResults)).toBeNull();
    expect(findDuplicateResultField({ name: 'Linked result', externalUri: 'https://openaev.io/simulations/2' }, existingResults)).toBeNull();
  });

  it('should not flag a new name', () => {
    expect(findDuplicateResultField({ name: 'Brand new result', externalUri: '' }, existingResults)).toBeNull();
  });

  it('should not flag anything without existing results', () => {
    expect(findDuplicateResultField({ name: 'Result of my coverage', externalUri: '' }, null)).toBeNull();
  });
});
