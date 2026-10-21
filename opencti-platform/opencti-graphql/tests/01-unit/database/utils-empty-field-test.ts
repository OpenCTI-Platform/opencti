import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { isEmptyField, isNotEmptyField } from '../../../src/database/utils';

// isNotEmptyField has a fast path; it must answer exactly as the ramda expression it replaces
const reference = (value: any) => !R.isEmpty(value) && !R.isNil(value);

class Plain {}
class WithField {
  name = 'x';
}
class ArraySubclass extends Array {}

const values: [string, any][] = [
  ['undefined', undefined],
  ['null', null],
  ['empty string', ''],
  ['space', ' '],
  ['string', 'value'],
  ['zero', 0],
  ['number', 42],
  ['NaN', Number.NaN],
  ['false', false],
  ['true', true],
  ['empty array', []],
  ['array', [1]],
  ['array of empty', ['']],
  ['empty object', {}],
  ['object', { a: 1 }],
  ['object with undefined value', { a: undefined }],
  ['null prototype empty', Object.create(null)],
  ['null prototype with key', Object.assign(Object.create(null), { a: 1 })],
  ['class instance without fields', new Plain()],
  ['class instance with fields', new WithField()],
  ['array subclass empty', new ArraySubclass()],
  ['date', new Date('2026-01-01')],
  ['empty map', new Map()],
  ['map', new Map([['a', 1]])],
  ['empty set', new Set()],
  ['set', new Set([1])],
  ['empty typed array', new Uint8Array(0)],
  ['typed array', new Uint8Array(2)],
  ['function', () => 1],
  ['object with empty method', { empty: () => ({}) }],
  ['string object', new String('')],
  ['symbol', Symbol('s')],
  ['bigint', BigInt(1)],
];

describe('isNotEmptyField', () => {
  it.each(values)('answers like R.isEmpty / R.isNil for %s', (_label, value) => {
    expect(isNotEmptyField(value)).toBe(reference(value));
    expect(isEmptyField(value)).toBe(!reference(value));
  });
});
