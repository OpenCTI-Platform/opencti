import { describe, expect, it } from 'vitest';
import { fingerprintOf, isUnchangedOn } from '../../../src/database/lockfree/unchanged';

const marking = { internal_id: 'm1', entity_type: 'Marking-Definition', definition_type: 'TLP', x_opencti_order: 1, updated_at: '2026-01-01' };
const author = { internal_id: 'a1', entity_type: 'Organization', name: 'Author', updated_at: '2026-01-01' };
const patch = { name: 'Indicator', pattern: "[url:value = 'x']", createdBy: author, objectMarking: [marking], confidence: 80 };

describe('Lock-free unchanged imports: fingerprint', () => {
  it('is the same for the same patch, whatever the order of its fields', () => {
    const reordered = { confidence: 80, objectMarking: [marking], createdBy: author, pattern: "[url:value = 'x']", name: 'Indicator' };
    expect(fingerprintOf('epoch', 'Indicator', null, reordered)).toEqual(fingerprintOf('epoch', 'Indicator', null, patch));
  });

  it('reads a resolved ref as what the merge compares of it', () => {
    const otherCopy = { ...patch, createdBy: { ...author, name: 'Renamed', updated_at: '2026-02-01' } };
    expect(fingerprintOf('epoch', 'Indicator', null, otherCopy)).toEqual(fingerprintOf('epoch', 'Indicator', null, patch));
    const otherAuthor = { ...patch, createdBy: { ...author, internal_id: 'a2' } };
    expect(fingerprintOf('epoch', 'Indicator', null, otherAuthor)).not.toEqual(fingerprintOf('epoch', 'Indicator', null, patch));
    const otherOrder = { ...patch, objectMarking: [{ ...marking, x_opencti_order: 2 }] };
    expect(fingerprintOf('epoch', 'Indicator', null, otherOrder)).not.toEqual(fingerprintOf('epoch', 'Indicator', null, patch));
  });

  it('changes with the value of any field, the type, the epoch and the entity settings', () => {
    const base = fingerprintOf('epoch', 'Indicator', { id: 's' }, patch);
    expect(fingerprintOf('epoch', 'Indicator', { id: 's' }, { ...patch, confidence: 81 })).not.toEqual(base);
    expect(fingerprintOf('epoch', 'Indicator', { id: 's' }, { ...patch, description: 'new' })).not.toEqual(base);
    expect(fingerprintOf('epoch', 'Report', { id: 's' }, patch)).not.toEqual(base);
    expect(fingerprintOf('other epoch', 'Indicator', { id: 's' }, patch)).not.toEqual(base);
    expect(fingerprintOf('epoch', 'Indicator', { id: 's', enforce_reference: true }, patch)).not.toEqual(base);
  });

  it('is not given to merges that read or write outside the object', () => {
    expect(fingerprintOf('epoch', 'Indicator', null, { ...patch, upsertOperations: [{ key: 'name', value: ['x'] }] })).toBeUndefined();
    expect(fingerprintOf('epoch', 'Report', null, { ...patch, description: '![x](data:image/png;base64,AAAA)' })).toBeUndefined();
  });
});

describe('Lock-free unchanged imports: known answers', () => {
  const known = new Map([['o1|f1', { seq_no: 12, primary_term: 1 }]]);

  it('holds only on the version it was found on', () => {
    expect(isUnchangedOn(known, 'o1', 'f1', { seq_no: 12, primary_term: 1 })).toBe(true);
    expect(isUnchangedOn(known, 'o1', 'f1', { seq_no: 13, primary_term: 1 })).toBe(false);
    expect(isUnchangedOn(known, 'o1', 'f1', { seq_no: 12, primary_term: 2 })).toBe(false);
  });

  it('needs a fingerprint, the same one, and a version read in the chunk', () => {
    expect(isUnchangedOn(known, 'o1', 'f2', { seq_no: 12, primary_term: 1 })).toBe(false);
    expect(isUnchangedOn(known, 'o2', 'f1', { seq_no: 12, primary_term: 1 })).toBe(false);
    expect(isUnchangedOn(known, 'o1', undefined, { seq_no: 12, primary_term: 1 })).toBe(false);
    expect(isUnchangedOn(known, 'o1', 'f1', undefined)).toBe(false);
  });
});
