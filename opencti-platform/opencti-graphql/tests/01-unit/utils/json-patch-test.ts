import { describe, expect, it } from 'vitest';
import * as jsonpatch from 'fast-json-patch';
import { computeJsonPatch, MAX_ARRAY_EDIT_DISTANCE } from '../../../src/utils/json-patch';

const applyPatch = (document: unknown, operations: jsonpatch.Operation[]) => {
  return jsonpatch.applyPatch(structuredClone(document), operations, true).newDocument;
};

const stixIds = (count: number) => Array.from({ length: count }, (_, index) => `report--${String(index).padStart(36, '0')}`);

const createRandom = (seed: number) => {
  let state = seed;
  return (bound: number) => {
    state = (state * 1103515245 + 12345) % 2147483648;
    return state % bound;
  };
};

const longestCommonSubsequence = (from: unknown[], to: unknown[]) => {
  const lengths = Array.from({ length: from.length + 1 }, () => new Array<number>(to.length + 1).fill(0));
  for (let x = 1; x <= from.length; x += 1) {
    for (let y = 1; y <= to.length; y += 1) {
      lengths[x][y] = from[x - 1] === to[y - 1] ? lengths[x - 1][y - 1] + 1 : Math.max(lengths[x - 1][y], lengths[x][y - 1]);
    }
  }
  return lengths[from.length][to.length];
};

describe('computeJsonPatch', () => {
  it('should insert a single element in the middle of an array', () => {
    const from = { values: ['a', 'b', 'd', 'e', 'f', 'g'] };
    const to = { values: ['a', 'b', 'c', 'd', 'e', 'f', 'g'] };
    expect(computeJsonPatch(from, to)).toEqual([{ op: 'add', path: '/values/2', value: 'c' }]);
    expect(computeJsonPatch(to, from)).toEqual([{ op: 'remove', path: '/values/2' }]);
  });

  it('should remove a single reference from a large container', () => {
    const objectRefs = stixIds(5000);
    const from = { object_refs: objectRefs };
    const to = { object_refs: objectRefs.filter((_, index) => index !== 10) };
    expect(computeJsonPatch(from, to)).toEqual([{ op: 'remove', path: '/object_refs/10' }]);
    expect(computeJsonPatch(to, from)).toEqual([{ op: 'add', path: '/object_refs/10', value: objectRefs[10] }]);
  });

  it('should replace an element changed in place', () => {
    expect(computeJsonPatch({ values: ['a', 'b', 'c'] }, { values: ['a', 'x', 'c'] }))
      .toEqual([{ op: 'replace', path: '/values/1', value: 'x' }]);
  });

  it('should diff inside an object changed in place in an array', () => {
    const from = { external_references: [{ source_name: 'a', url: 'u1' }, { source_name: 'b', url: 'u2' }, { source_name: 'c', url: 'u3' }] };
    const to = { external_references: [{ source_name: 'a', url: 'u1' }, { source_name: 'b', url: 'u2b' }, { source_name: 'c', url: 'u3' }] };
    expect(computeJsonPatch(from, to)).toEqual([{ op: 'replace', path: '/external_references/1/url', value: 'u2b' }]);
  });

  it('should insert an object in an array without touching the following ones', () => {
    const from = { external_references: [{ source_name: 'a' }, { source_name: 'b' }] };
    const to = { external_references: [{ source_name: 'a' }, { source_name: 'n' }, { source_name: 'b' }] };
    expect(computeJsonPatch(from, to)).toEqual([{ op: 'add', path: '/external_references/1', value: { source_name: 'n' } }]);
  });

  it('should diff objects sharing an id field by field', () => {
    const objects = Array.from({ length: 2000 }, (_, index) => ({ id: `indicator--${index}`, object_marking_refs: ['marking-definition--a'] }));
    const from = { objects };
    const to = { objects: objects.map((object) => ({ ...object, object_marking_refs: [...object.object_marking_refs, 'marking-definition--b'] })) };
    const operations = computeJsonPatch(from, to);
    expect(operations).toHaveLength(2000);
    expect(operations[0]).toEqual({ op: 'add', path: '/objects/0/object_marking_refs/1', value: 'marking-definition--b' });
    expect(applyPatch(from, operations)).toEqual(to);
  });

  it('should remove an object by id and diff the others in place', () => {
    const from = { objects: [{ id: 'a', name: 'a' }, { id: 'b', name: 'b' }, { id: 'c', name: 'c' }] };
    const to = { objects: [{ id: 'a', name: 'a' }, { id: 'c', name: 'c2' }] };
    expect(computeJsonPatch(from, to)).toEqual([
      { op: 'remove', path: '/objects/1' },
      { op: 'replace', path: '/objects/1/name', value: 'c2' },
    ]);
  });

  it('should not confuse an object with a string holding its JSON', () => {
    expect(computeJsonPatch({ values: [{ a: 1 }, 'k'] }, { values: ['{"a":1}', 'k'] })).toEqual([{ op: 'replace', path: '/values/0', value: '{"a":1}' }]);
    expect(computeJsonPatch({ values: [{ id: 'x' }, 'k'] }, { values: ['#x', 'k'] })).toEqual([{ op: 'replace', path: '/values/0', value: '#x' }]);
  });

  it('should add, remove and replace object properties', () => {
    const from = { name: 'before', description: 'removed', 'a/b~c': 1 };
    const to = { name: 'after', 'a/b~c': 2, labels: ['new'] };
    expect(computeJsonPatch(from, to)).toEqual([
      { op: 'replace', path: '/name', value: 'after' },
      { op: 'remove', path: '/description' },
      { op: 'replace', path: '/a~1b~0c', value: 2 },
      { op: 'add', path: '/labels', value: ['new'] },
    ]);
  });

  it('should treat undefined properties as absent', () => {
    expect(computeJsonPatch({ name: 'a', description: undefined }, { name: 'a' })).toEqual([]);
    expect(computeJsonPatch({ name: 'a' }, { name: 'a', description: undefined })).toEqual([]);
  });

  it('should replace a value whose type changes', () => {
    expect(computeJsonPatch({ value: ['a'] }, { value: { a: 1 } })).toEqual([{ op: 'replace', path: '/value', value: { a: 1 } }]);
    expect(computeJsonPatch({ value: 'a' }, { value: null })).toEqual([{ op: 'replace', path: '/value', value: null }]);
  });

  it('should not share values between the patch and the target document', () => {
    const to = { values: [{ name: 'a' }] };
    const [operation] = computeJsonPatch({ values: [] }, to);
    expect(operation).toEqual({ op: 'add', path: '/values/0', value: { name: 'a' } });
    expect((operation as jsonpatch.AddOperation<unknown>).value).not.toBe(to.values[0]);
  });

  it('should replace the whole array when the edit distance exceeds the target length', () => {
    expect(computeJsonPatch({ values: ['a', 'b', 'c'] }, { values: [] })).toEqual([{ op: 'replace', path: '/values', value: [] }]);
    expect(computeJsonPatch({ values: ['a', 'b', 'c'] }, { values: ['x'] })).toEqual([{ op: 'replace', path: '/values', value: ['x'] }]);
  });

  it('should replace the whole array when the edit distance exceeds the limit', () => {
    const from = { object_refs: stixIds(5000) };
    const to = { object_refs: stixIds(5000).map((id) => `${id}z`) };
    expect(computeJsonPatch(from, to)).toEqual([{ op: 'replace', path: '/object_refs', value: to.object_refs }]);
  });

  it('should keep an edit script up to the limit', () => {
    const objectRefs = stixIds(2 * MAX_ARRAY_EDIT_DISTANCE);
    const from = { object_refs: objectRefs };
    const to = { object_refs: objectRefs.filter((_, index) => index % 2 === 0) };
    const operations = computeJsonPatch(from, to);
    expect(operations).toHaveLength(MAX_ARRAY_EDIT_DISTANCE);
    expect(operations.every((operation) => operation.op === 'remove')).toBe(true);
    expect(applyPatch(from, operations)).toEqual(to);
  });

  it('should produce minimal patches that rebuild the target on random arrays', () => {
    const random = createRandom(13078);
    for (let iteration = 0; iteration < 2000; iteration += 1) {
      const alphabet = 1 + random(6);
      const from = Array.from({ length: random(12) }, () => String.fromCharCode(97 + random(alphabet)));
      const to = Array.from({ length: random(12) }, () => String.fromCharCode(97 + random(alphabet)));
      const operations = computeJsonPatch({ values: from }, { values: to });
      expect(applyPatch({ values: from }, operations)).toEqual({ values: to });
      if (operations.length !== 1 || operations[0].path !== '/values') {
        const weight = operations.reduce((total, operation) => total + (operation.op === 'replace' ? 2 : 1), 0);
        expect(weight).toBe(from.length + to.length - 2 * longestCommonSubsequence(from, to));
      }
    }
  });

  it('should rebuild the target on random nested documents', () => {
    const random = createRandom(42);
    const randomValue = (depth: number): unknown => {
      const kind = random(depth > 2 ? 3 : 5);
      if (kind === 0) return random(4);
      if (kind === 1) return String.fromCharCode(97 + random(4));
      if (kind === 2) return random(2) === 0 ? null : random(2) === 0;
      if (kind === 3) return Array.from({ length: random(5) }, () => randomValue(depth + 1));
      return Object.fromEntries(Array.from({ length: random(4) }, () => [['id', 'k', 'l', 'm'][random(4)], randomValue(depth + 1)]));
    };
    for (let iteration = 0; iteration < 2000; iteration += 1) {
      const from = randomValue(0);
      const to = randomValue(0);
      expect(applyPatch(from, computeJsonPatch(from, to))).toEqual(to);
      expect(applyPatch(to, computeJsonPatch(to, from))).toEqual(from);
    }
  });
});
