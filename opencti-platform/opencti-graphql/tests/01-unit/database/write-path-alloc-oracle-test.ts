import { afterEach, describe, expect, it, vi } from 'vitest';
import * as R from 'ramda';
import { performance } from 'node:perf_hooks';
import { setImmediate as setImmediateAsync } from 'node:timers/promises';
import '../../../src/modules/index';
import { prepareElementForIndexing } from '../../../src/database/engine';
import { removeResolvedRefs } from '../../../src/database/redis';
import { shouldYield } from '../../../src/utils/eventloop-utils';
import { INPUT_OBJECTS } from '../../../src/schema/general';
import { isBooleanAttribute, isDateAttribute, isNumericAttribute, isObjectRawAttribute } from '../../../src/schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';
import { isNotEmptyField } from '../../../src/database/utils';

// region reference: the implementations before the allocation fixes (@7e9e2efbe3)
const MAX_EVENT_LOOP_PROCESSING_TIME = 50;
const makeReferenceYield = () => {
  let nextYield: number | undefined;
  return async (): Promise<boolean> => {
    const now = performance.now();
    if (nextYield !== undefined) {
      if (now > nextYield) {
        nextYield = undefined;
        await setImmediateAsync();
        return true;
      }
    } else {
      nextYield = now + MAX_EVENT_LOOP_PROCESSING_TIME;
    }
    return false;
  };
};
const referenceDoYield = makeReferenceYield();
const prepareElementForIndexingReference = async (element: Record<string, any>): Promise<Record<string, any>> => {
  const thing: Record<string, any> = {};
  const keyItems = Object.keys(element);
  for (let index = 0; index < keyItems.length; index += 1) {
    await referenceDoYield();
    const key = keyItems[index];
    const value = element[key];
    if (Array.isArray(value)) {
      const preparedArray = [];
      for (let valueIndex = 0; valueIndex < value.length; valueIndex += 1) {
        await referenceDoYield();
        const valueElement = value[valueIndex];
        if (valueElement) {
          if (isDateAttribute(key)) {
            preparedArray.push(valueElement);
          } else if (R.is(String, valueElement)) {
            preparedArray.push(valueElement.trim());
          } else if (R.is(Object, valueElement) && Object.keys(value).length > 0) {
            const complexPrepared = await prepareElementForIndexingReference(valueElement);
            preparedArray.push(complexPrepared);
          } else {
            preparedArray.push(valueElement);
          }
        }
      }
      thing[key] = preparedArray;
    } else if (isDateAttribute(key)) {
      thing[key] = value;
    } else if (isBooleanAttribute(key)) {
      thing[key] = typeof value === 'boolean' ? value : value?.toLowerCase() === 'true';
    } else if (isNumericAttribute(key)) {
      thing[key] = isNotEmptyField(value) ? Number(value) : undefined;
    } else if (R.is(Object, value) && Object.keys(value).length > 0 && !isObjectRawAttribute(key)) {
      thing[key] = await prepareElementForIndexingReference(value);
    } else if (R.is(String, value)) {
      thing[key] = value.trim();
    } else {
      thing[key] = value;
    }
  }
  return thing;
};
const removeResolvedRefsReference = (instance: any) => {
  const refInputNames = new Set([INPUT_OBJECTS, ...schemaRelationsRefDefinition.getAllInputNames()]);
  return Object.fromEntries(Object.entries(instance).filter(([k]) => !refInputNames.has(k)));
};
// endregion

const sameObject = (actual: any, expected: any) => {
  expect(actual).toStrictEqual(expected);
  expect(JSON.stringify(actual)).toEqual(JSON.stringify(expected));
  expect(Object.getPrototypeOf(actual)).toBe(Object.getPrototypeOf(expected));
  expect(Reflect.ownKeys(actual)).toEqual(Reflect.ownKeys(expected));
};

// seeded generator of indexed documents: schema-typed keys (dates, booleans, numerics, raw objects) and
// free keys, arrays of strings / dates / objects / falsy values, sparse arrays, nesting
const makeRandom = (seed: number) => {
  let state = seed;
  return () => {
    state = (state * 1103515245 + 12345) % 2147483648;
    return state / 2147483648;
  };
};
const generateDocument = (rand: () => number, depth = 0): Record<string, any> => {
  const pick = <T>(values: T[]): T => values[Math.floor(rand() * values.length)];
  const doc: Record<string, any> = {
    internal_id: `id-${Math.floor(rand() * 1e6)}`,
    name: pick(['  spaced name  ', 'plain', '', '\tTabbed\n']),
    created_at: pick([new Date(1700000000000), '2024-01-01T00:00:00.000Z', null]),
    revoked: pick([true, false, 'true', 'FALSE', 'yes', undefined]),
    confidence: pick([85, '42', '', null, undefined, 'abc']),
    x_opencti_score: pick([10, '7']),
    aliases: pick([[' a ', 'b', '', null, 'c '], [], ['only']]),
    i_aliases_ids: pick([['aliases--1'], []]),
    external_references: pick([[{ source_name: ' MITRE ', url: 'http://x ', external_id: 'T1' }, null, 0], []]),
    custom_field_values: pick([{ field_a: ' v ', nested: { x: ' y ' } }, {}, null]),
    rel_object: pick([['obj--1', 'obj--2'], undefined]),
    entity_type: 'Report',
    published: pick([['2024-01-01T00:00:00.000Z', new Date(0)], '2024-01-01T00:00:00.000Z']),
    description: pick([' text ', 0, false, 12.5]),
    flat_object: pick([{ a: 1 }, {}]),
  };
  const sparse: any[] = [];
  sparse[3] = ' sparse ';
  if (rand() < 0.3) doc.sparse_values = sparse;
  if (rand() < 0.3) doc.mixed_values = [' s ', 1, true, false, { inner: ' i ' }, new Date(5), ['nested ', ' array']];
  if (depth < 2 && rand() < 0.4) doc.child = generateDocument(rand, depth + 1);
  if (depth < 2 && rand() < 0.4) doc.children = [generateDocument(rand, depth + 1), generateDocument(rand, depth + 1)];
  const big = Math.floor(rand() * 400);
  if (big > 300) doc.object_refs = Array.from({ length: big }, (_, i) => ` ref-${i} `);
  return doc;
};

describe('prepareElementForIndexing: same documents as the awaited doYield version', () => {
  afterEach(() => vi.restoreAllMocks());

  it('should prepare 2,000 random documents exactly as the former implementation', async () => {
    const rand = makeRandom(7);
    for (let i = 0; i < 2000; i += 1) {
      const doc = generateDocument(rand);
      const expected = await prepareElementForIndexingReference(doc);
      const actual = await prepareElementForIndexing(doc);
      sameObject(actual, expected);
    }
  });

  it('should still yield to the event loop on long documents and keep the result', async () => {
    // a clock moving 1 ms per call, past any deadline already armed by the real clock, forces a yield
    // every ~50 calls; an immediate scheduled before only runs if the preparation yields
    let clock = performance.now() + 1000;
    vi.spyOn(performance, 'now').mockImplementation(() => {
      clock += 1;
      return clock;
    });
    // consume any armed deadline (shared module state), so that only the array loop can yield
    while (!shouldYield());
    let immediateRan = false;
    setImmediate(() => {
      immediateRan = true;
    });
    const doc = { object_refs: Array.from({ length: 5000 }, (_, i) => ` ref-${i} `), name: ' n ' };
    const actual = await prepareElementForIndexing(doc);
    expect(actual.object_refs).toHaveLength(5000);
    expect(actual.object_refs[0]).toEqual('ref-0');
    expect(actual.name).toEqual('n');
    expect(immediateRan).toBe(true);
  });
});

describe('shouldYield / doYield: same decisions as the former doYield', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.resetModules();
  });

  it('should take the same yield decisions on the same clock', async () => {
    const rand = makeRandom(11);
    const clockValues = Array.from({ length: 5000 }, (_, i) => i * 3 + Math.floor(rand() * 40));
    clockValues.sort((a, b) => a - b);
    const run = async (yieldFn: () => Promise<boolean>) => {
      let callIndex = 0;
      const spy = vi.spyOn(performance, 'now').mockImplementation(() => clockValues[callIndex]);
      const decisions: boolean[] = [];
      for (callIndex = 0; callIndex < clockValues.length; callIndex += 1) {
        decisions.push(await yieldFn());
      }
      spy.mockRestore();
      return decisions;
    };
    const expected = await run(makeReferenceYield());
    vi.resetModules(); // a fresh module: no deadline armed by an earlier test
    const { doYield } = await import('../../../src/utils/eventloop-utils');
    const actual = await run(doYield);
    expect(actual).toEqual(expected);
    expect(actual.filter((d) => d).length).toBeGreaterThan(10);
  });

  it('should give with shouldYield the decisions doYield gives', async () => {
    const clockValues = Array.from({ length: 2000 }, (_, i) => i * 7);
    let callIndex = 0;
    vi.spyOn(performance, 'now').mockImplementation(() => clockValues[callIndex]);
    const expectedYield = makeReferenceYield();
    const expected: boolean[] = [];
    for (callIndex = 0; callIndex < clockValues.length; callIndex += 1) {
      expected.push(await expectedYield());
    }
    vi.resetModules();
    const { shouldYield } = await import('../../../src/utils/eventloop-utils');
    const actual: boolean[] = [];
    for (callIndex = 0; callIndex < clockValues.length; callIndex += 1) {
      actual.push(shouldYield());
    }
    expect(actual).toEqual(expected);
  });
});

describe('removeResolvedRefs: same object as the Object.fromEntries version', () => {
  it('should strip the same keys and keep the same key order and properties', () => {
    const refNames = [INPUT_OBJECTS, ...schemaRelationsRefDefinition.getAllInputNames()];
    const rand = makeRandom(3);
    for (let i = 0; i < 2000; i += 1) {
      const instance: Record<string, any> = {};
      const keyCount = Math.floor(rand() * 30);
      for (let k = 0; k < keyCount; k += 1) {
        const roll = rand();
        let key: string;
        if (roll < 0.3) key = refNames[Math.floor(rand() * refNames.length)];
        else if (roll < 0.4) key = String(Math.floor(rand() * 20));
        else key = `field_${Math.floor(rand() * 50)}`;
        instance[key] = rand() < 0.5 ? { id: key } : [key, k];
      }
      sameObject(removeResolvedRefs(instance), removeResolvedRefsReference(instance));
    }
  });

  it('should keep an own __proto__ key as a plain property, inherited and non-enumerable keys out', () => {
    const parsed = JSON.parse('{"name":"a","__proto__":{"polluted":true},"objects":[1],"createdBy":{"id":"x"},"2":"two"}');
    const expected = removeResolvedRefsReference(parsed);
    const actual = removeResolvedRefs(parsed);
    sameObject(actual, expected);
    expect(Object.getPrototypeOf(actual)).toBe(Object.prototype);
    expect(Object.getOwnPropertyDescriptor(actual, '__proto__')).toEqual(Object.getOwnPropertyDescriptor(expected, '__proto__'));
    const inherited = Object.create({ inheritedKey: 1 });
    inherited.own = 2;
    Object.defineProperty(inherited, 'hidden', { value: 3, enumerable: false });
    sameObject(removeResolvedRefs(inherited), removeResolvedRefsReference(inherited));
  });

  it('should read each getter once, as Object.entries does', () => {
    let reads = 0;
    const instance = {
      get computed() {
        reads += 1;
        return reads;
      },
      name: 'n',
    };
    const actual = removeResolvedRefs(instance);
    expect(reads).toEqual(1);
    expect(actual).toEqual({ computed: 1, name: 'n' });
  });
});
