import { describe, expect, it } from 'vitest';
import { keepMostRestrictiveTypes } from '../../../src/schema/schemaUtils';

describe('Schema Utils tests', () => {
  it('keepMostRestrictiveTypes should keep all types if no overlap', () => {
    const types = keepMostRestrictiveTypes(['Report', 'City']);
    expect(types.length).toEqual(2);
    expect(types).toContain('Report');
    expect(types).toContain('City');
  });
  it('keepMostRestrictiveTypes should keep most restrictive types', () => {
    const types = keepMostRestrictiveTypes(['Report', 'Stix-Domain-Object', 'City']);
    expect(types.length).toEqual(2);
    expect(types).toContain('Report');
    expect(types).toContain('City');
  });
  it('keepMostRestrictiveTypes should keep abstract types', () => {
    const types = keepMostRestrictiveTypes(['Stix-Domain-Object']);
    expect(types.length).toEqual(1);
    expect(types).toContain('Stix-Domain-Object');
  });
  it('keepMostRestrictiveTypes should keep most restrictive abstract types', () => {
    const types = keepMostRestrictiveTypes(['Stix-Domain-Object', 'Stix-Core-Object']);
    expect(types.length).toEqual(1);
    expect(types).toContain('Stix-Domain-Object');
  });
});
