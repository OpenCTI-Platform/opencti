import { describe, it, expect } from 'vitest';
import '../../../../src/modules/index';

import { completeEntity } from '../../../../src/modules/form/form-entity-builder';
import { generateStandardId } from '../../../../src/schema/identifier';

describe('completeEntity', () => {
  it('sets standard_id, internal_id and id', () => {
    const entity: any = { name: 'Test Malware' };
    const result = completeEntity('Malware', entity);

    expect(result.standard_id).toBeDefined();
    expect(result.internal_id).toBe(result.id);
    expect(result.id).toBe(result.internal_id);
  });

  it('returns the mutated entity (same reference)', () => {
    const entity: any = { name: 'Test' };
    expect(completeEntity('Malware', entity)).toBe(entity);
  });

  it('sets created and modified for a StixDomainObject', () => {
    const entity: any = { name: 'Test Malware' };
    const result = completeEntity('Malware', entity);

    expect(result.created).toBeInstanceOf(Date);
    expect(result.modified).toBeInstanceOf(Date);
  });

  it('does not override created/modified when already set', () => {
    const created = new Date('2023-01-01');
    const modified = new Date('2023-06-15');
    const entity: any = { name: 'Test', created, modified };
    const result = completeEntity('Malware', entity);

    expect(result.created).toBe(created);
    expect(result.modified).toBe(modified);
  });

  it('does not set created/modified for a non-SDO type', () => {
    const entity: any = { name: 'Test' };
    const result = completeEntity('StixFile', entity);

    expect(result.created).toBeUndefined();
    expect(result.modified).toBeUndefined();
  });

  // The platform recomputes the id from the stored values: the bundle id must be the same, or refs to the entity are lost
  it.each([
    ['Task', { name: 'Form task' }],
    ['Case-Incident', { name: 'Form incident response' }],
    ['Note', { content: 'Form note' }],
  ])('computes the standard_id of a %s from the created it sets', (type, input) => {
    const result = completeEntity(type, { ...input } as any);

    expect(result.standard_id).toEqual(generateStandardId(type, { ...input, created: result.created.toISOString() } as any));
  });

  it('computes the standard_id of an identity from its identity_class', () => {
    const result = completeEntity('Individual', { name: 'Form individual' } as any);

    expect(result.standard_id).toEqual(generateStandardId('Individual', { name: 'Form individual', identity_class: 'individual' } as any));
  });
});
