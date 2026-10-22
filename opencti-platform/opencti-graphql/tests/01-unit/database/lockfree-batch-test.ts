import { describe, expect, it } from 'vitest';
import { dependenciesOf, replaceStrings } from '../../../src/database/lockfree/batch';

const op = (ref: string | null, variables: Record<string, any> = {}) => ({ ref, query: 'mutation { x }', variables });

describe('Lock-free batch import: operations order', () => {
  it('waits for the operations an operation references, wherever the reference is', () => {
    const deps = dependenciesOf([
      op('identity--a'),
      op('external-reference--b'),
      op('intrusion-set--c', { input: { createdBy: 'identity--a', externalReferences: ['external-reference--b'], name: 'C' } }),
      op('relationship--d', { input: { fromId: 'intrusion-set--c', toId: 'malware--outside' } }),
    ]);
    expect(deps).toEqual([[], [], [0, 1], [2]]);
  });

  it('ignores references to itself and to objects outside the batch', () => {
    const deps = dependenciesOf([op('report--a', { input: { stix_id: 'report--a', objects: ['malware--outside'] } })]);
    expect(deps).toEqual([[]]);
  });

  it('breaks a cycle instead of waiting forever', () => {
    const deps = dependenciesOf([
      op('note--a', { input: { objects: ['note--b'] } }),
      op('note--b', { input: { objects: ['note--a'] } }),
    ]);
    const edges = deps.flat().length;
    expect(edges).toBe(1);
  });

  it('replaces placeholders with the real ids, deep, and nothing else', () => {
    const ids = new Map([['identity--a', 'uuid-a'], ['label--b', 'uuid-b']]);
    const variables = { input: { createdBy: 'identity--a', objectLabel: ['label--b', 'other'], nested: [{ x: 'identity--a' }], count: 3, flag: true } };
    expect(replaceStrings(variables, ids)).toEqual({
      input: { createdBy: 'uuid-a', objectLabel: ['uuid-b', 'other'], nested: [{ x: 'uuid-a' }], count: 3, flag: true },
    });
  });
});
