import { describe, expect, it } from 'vitest';
import { computeBatchLockKeys } from '../../../src/database/sequencer/sequencer-batch-lock';

// fix 2026-09-22: the batch lock must hold every key an apply-time lock site will ask for
describe('sequencer batch lock keys', () => {
  const instance = new Map<string, string[]>([
    ['identity--org', ['int-org', 'identity--org', 'identity--org-stix']],
    ['marking-definition--tlp', ['int-tlp', 'marking-definition--tlp']],
  ]);
  const peek = (id: string) => instance.get(id) ?? null;
  const resolve = (id: string) => (id === 'identity--org' ? 'int-org' : null);

  it('holds the candidates, the referenced ids and their pre-resolved instance ids', () => {
    const groups = [{
      leader: { kind: 'entity', candidateIds: ['malware--m', 'malware--m-stix'], referencedIds: ['identity--org', 'marking-definition--tlp', 'label--x'], input: {} },
      absorbed: [{ referencedIds: ['external-reference--e'] }],
    }];
    const keys = new Set(computeBatchLockKeys(groups, peek, resolve));
    ['malware--m', 'malware--m-stix', 'identity--org', 'int-org', 'identity--org-stix', 'marking-definition--tlp', 'int-tlp', 'label--x', 'external-reference--e']
      .forEach((k) => expect(keys.has(k)).toBe(true));
  });

  it('resolves a relation endpoint to its internal id when the map knows it, keeps the raw id otherwise', () => {
    const groups = [{
      leader: { kind: 'relation', candidateIds: ['relationship--r', 'identity--org', 'malware--new'], referencedIds: ['identity--org', 'malware--new'], input: { fromId: 'malware--new', toId: 'identity--org' } },
      absorbed: [],
    }];
    const keys = new Set(computeBatchLockKeys(groups, peek, resolve));
    expect(keys.has('int-org')).toBe(true);
    expect(keys.has('malware--new')).toBe(true);
    expect(keys.has('relationship--r')).toBe(true);
  });

  it('ignores empty ids and deduplicates', () => {
    const groups = [{ leader: { kind: 'relation', candidateIds: ['a', 'a', ''], referencedIds: ['a'], input: { fromId: '', toId: 'a' } }, absorbed: [] }];
    expect(computeBatchLockKeys(groups, () => null, () => null)).toEqual(['a']);
  });
});
