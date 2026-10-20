import { describe, expect, it } from 'vitest';
import { findDuplicateResultField, resultToFormData, SecurityCoverageResultToEdit } from './SecurityCoverageResultForm-utils';

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

describe('resultToFormData', () => {
  const baseResult: SecurityCoverageResultToEdit = {
    id: 'scr-1',
    name: 'Manual result',
    description: null,
    confidence: null,
    external_uri: null,
    coverage_valid_from: null,
    coverage_valid_to: null,
    coverage_information: null,
    createdBy: null,
    objectMarking: null,
    objectLabel: null,
  };

  it('should fill the form with the values of the result', () => {
    const formData = resultToFormData({
      ...baseResult,
      description: 'Result of the red team exercise',
      confidence: 75,
      coverage_valid_from: '2026-01-01T00:00:00.000Z',
      coverage_valid_to: '2026-12-31T00:00:00.000Z',
      coverage_information: [{ coverage_name: 'detection', coverage_score: 80 }],
      createdBy: { id: 'identity-1', name: 'Filigran', entity_type: 'Organization' },
      objectMarking: [{ id: 'marking-1', definition: 'TLP:CLEAR', definition_type: 'TLP', x_opencti_color: '#fff', x_opencti_order: 1 }],
      objectLabel: [{ id: 'label-1', value: 'red-team', color: '#f00' }],
    });

    expect(formData.name).toEqual('Manual result');
    expect(formData.description).toEqual('Result of the red team exercise');
    expect(formData.confidence).toEqual(75);
    expect(formData.externalUri).toEqual('');
    expect(formData.validFrom).toEqual(new Date('2026-01-01T00:00:00.000Z'));
    expect(formData.validTo).toEqual(new Date('2026-12-31T00:00:00.000Z'));
    expect(formData.coverageInformation).toEqual([{ coverage_name: 'detection', coverage_score: 80 }]);
    expect(formData.createdBy).toEqual({ label: 'Filigran', value: 'identity-1', type: 'Organization' });
    expect(formData.objectMarking.map((m) => m.value)).toEqual(['marking-1']);
    expect(formData.objectLabel).toEqual([{ label: 'red-team', value: 'label-1', color: '#f00' }]);
  });

  it('should use empty values when the result has no optional data', () => {
    const formData = resultToFormData(baseResult);

    expect(formData.description).toEqual('');
    expect(formData.confidence).toBeUndefined();
    expect(formData.createdBy).toBeUndefined();
    expect(formData.objectMarking).toEqual([]);
    expect(formData.objectLabel).toEqual([]);
    expect(formData.validFrom).toBeNull();
    expect(formData.validTo).toBeNull();
    // At least one coverage score is required by the form
    expect(formData.coverageInformation).toEqual([{ coverage_name: null, coverage_score: null }]);
  });
});
