import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { isEmptyField, isNotEmptyField } from '../../../src/database/utils';

// Reference: the ramda based implementation the native one replaces
const isNotEmptyFieldReference = (field: any) => !R.isEmpty(field) && !R.isNil(field);
const isEmptyFieldReference = (field: any) => !isNotEmptyFieldReference(field);

class WithField {
  a = 1;
}
class EmptyClass {}
const buildEdgeCases = (): [string, unknown][] => {
  const sparse = new Array(3);
  const sparseTail = [, 1]; // eslint-disable-line no-sparse-arrays
  const arrayWithExtraProp: any = [];
  arrayWithExtraProp.foo = 1;
  const arrayWithOwnEquals: any = [1];
  arrayWithOwnEquals.equals = () => true;
  const emptyArrayWithOwnEquals: any = [];
  emptyArrayWithOwnEquals.equals = () => true;
  const arrayWithFantasyEmpty: any = [1];
  arrayWithFantasyEmpty['fantasy-land/empty'] = () => [1];
  const arrayWithHiddenIndex: any = [];
  Object.defineProperty(arrayWithHiddenIndex, 0, { value: 1, enumerable: false });
  const arrayWithTag: any = [];
  arrayWithTag[Symbol.toStringTag] = 'Foo';
  const arrayWithConstructor: any = [];
  arrayWithConstructor.constructor = { empty: () => [] };
  const arrayWithHiddenEquals: any = [];
  Object.defineProperty(arrayWithHiddenEquals, 'equals', { value: () => true, enumerable: false });
  const nullProtoEmpty = Object.create(null);
  const nullProtoFull = Object.create(null);
  nullProtoFull.a = 1;
  const nullProtoWithConstructor = Object.create(null);
  nullProtoWithConstructor.constructor = { empty: () => nullProtoWithConstructor };
  const objectWithHiddenProp = {};
  Object.defineProperty(objectWithHiddenProp, 'a', { value: 1, enumerable: false });
  const objectWithSymbolKey = { [Symbol('s')]: 1 };
  return [
    ['null', null], ['undefined', undefined], ['empty string', ''], ['space', ' '], ['string', 'a'],
    ['0', 0], ['-0', -0], ['1', 1], ['NaN', NaN], ['Infinity', Infinity], ['true', true], ['false', false],
    ['bigint', 10n], ['symbol', Symbol('s')],
    ['[]', []], ['[0]', [0]], ['[null]', [null]], ['[undefined]', [undefined]], ["['']", ['']], ['[[]]', [[]]],
    ['sparse', sparse], ['sparse tail', sparseTail], ['array extra prop', arrayWithExtraProp],
    ['array own equals', arrayWithOwnEquals], ['empty array own equals', emptyArrayWithOwnEquals],
    ['array fantasy-land/empty', arrayWithFantasyEmpty], ['array hidden index', arrayWithHiddenIndex],
    ['array toStringTag', arrayWithTag], ['array own constructor', arrayWithConstructor],
    ['array hidden equals', arrayWithHiddenEquals],
    ['{}', {}], ['{a: undefined}', { a: undefined }], ['{a: null}', { a: null }],
    ['null proto empty', nullProtoEmpty], ['null proto full', nullProtoFull], ['null proto constructor', nullProtoWithConstructor],
    ['own equals', { equals: () => true }], ['own empty', { a: 1, empty: () => ({ a: 1 }) }],
    ['own fantasy-land/empty', { a: 1, 'fantasy-land/empty': () => ({ a: 1 }) }],
    ['own fantasy-land/equals', { 'fantasy-land/equals': () => true }],
    ['own constructor value', { constructor: 'x' }], ['own constructor empty', { constructor: { empty: () => ({}) } }],
    ['own Promise constructor', { constructor: function Promise() {} }],
    ['object toStringTag', { [Symbol.toStringTag]: 'Foo' }], ['object toStringTag Object', { [Symbol.toStringTag]: 'Object' }],
    ['object hidden prop', objectWithHiddenProp], ['object symbol key', objectWithSymbolKey],
    ['inherited only', Object.create({ x: 1 })], ['inherited empty', Object.create({})],
    ['Date', new Date()], ['invalid Date', new Date(NaN)], ['Map', new Map()], ['Map full', new Map([[1, 1]])],
    ['Set', new Set()], ['Set full', new Set([1])], ['Buffer empty', Buffer.alloc(0)], ['Buffer', Buffer.from('x')],
    ['Uint8Array empty', new Uint8Array(0)], ['Uint8Array', new Uint8Array(2)],
    ['String object empty', new String('')], ['String object', new String('a')],
    ['Number object', new Number(0)], ['Boolean object', new Boolean(false)],
    ['class instance', new WithField()], ['empty class instance', new EmptyClass()],
    ['arrow function', () => 1], ['function', function f() {}], ['RegExp', /x/], ['Error', new Error('e')],
    ['Promise', Promise.resolve(1)],
    ['arguments empty', (function args() {
      return arguments; // eslint-disable-line prefer-rest-params
    }())],
    ['arguments', (function args(_a: number) {
      return arguments; // eslint-disable-line prefer-rest-params
    }(1))],
  ];
};

// Deterministic generator of JSON like values, the shapes found in element inputs
const seededRandom = (seed: number) => {
  let state = seed;
  return () => {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    return state / 0x7fffffff;
  };
};
const generateValue = (random: () => number, depth: number): unknown => {
  const kind = Math.floor(random() * (depth > 2 ? 7 : 10));
  switch (kind) {
    case 0: return null;
    case 1: return undefined;
    case 2: return random() < 0.3 ? '' : `v${Math.floor(random() * 100)}`;
    case 3: return Math.floor(random() * 3) - 1;
    case 4: return random() < 0.5;
    case 5: return random() < 0.5 ? new Date(Math.floor(random() * 1e12)) : ' ';
    case 6: return random() < 0.5 ? [] : {};
    case 7: return Array.from({ length: Math.floor(random() * 3) }, () => generateValue(random, depth + 1));
    case 8: {
      const obj: Record<string, unknown> = {};
      const size = Math.floor(random() * 3);
      for (let i = 0; i < size; i += 1) obj[`k${i}`] = generateValue(random, depth + 1);
      return obj;
    }
    default: {
      const obj = Object.create(null);
      if (random() < 0.5) obj.a = generateValue(random, depth + 1);
      return obj;
    }
  }
};

describe('isEmptyField / isNotEmptyField native equivalence with ramda', () => {
  it.each(buildEdgeCases())('should match ramda on %s', (_label, value) => {
    expect(isNotEmptyField(value)).toBe(isNotEmptyFieldReference(value));
    expect(isEmptyField(value)).toBe(isEmptyFieldReference(value));
  });

  it('should match ramda on generated values and their nested members', () => {
    const random = seededRandom(42);
    let checked = 0;
    const check = (value: unknown) => {
      expect(isNotEmptyField(value)).toBe(isNotEmptyFieldReference(value));
      expect(isEmptyField(value)).toBe(isEmptyFieldReference(value));
      checked += 1;
      if (value !== null && typeof value === 'object') {
        Object.values(value).forEach(check);
      }
    };
    for (let i = 0; i < 5000; i += 1) check(generateValue(random, 0));
    expect(checked).toBeGreaterThan(5000);
  });

  it('should match ramda when Object.prototype carries an enumerable property', () => {
    const proto = Object.prototype as any;
    proto.pollutedTestKey = 1;
    try {
      buildEdgeCases().forEach(([, value]) => {
        expect(isNotEmptyField(value)).toBe(isNotEmptyFieldReference(value));
      });
    } finally {
      delete proto.pollutedTestKey;
    }
  });
});
