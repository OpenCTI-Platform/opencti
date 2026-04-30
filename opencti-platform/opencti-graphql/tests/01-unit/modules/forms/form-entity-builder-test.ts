import { describe, it, expect, vi } from 'vitest';

vi.mock('uuid', () => ({ v4: () => 'test-uuid-1234' }));

import { completeEntity } from '../../../../src/modules/form/form-entity-builder';

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
    const result = completeEntity('DraftWorkspace', entity);

    expect(result.created).toBeUndefined();
    expect(result.modified).toBeUndefined();
  });
});
