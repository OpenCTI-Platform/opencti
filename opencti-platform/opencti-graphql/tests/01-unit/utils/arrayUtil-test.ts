import { describe, expect, it } from 'vitest';
import { pushAll, unshiftAll } from '../../../src/utils/arrayUtil';

describe('Array utilities: pushAll', () => {
  it('should push all elements from a normal array', () => {
    const target = [1, 2, 3];
    const source = [4, 5, 6];
    const result = pushAll(target, source);

    expect(target).toEqual([1, 2, 3, 4, 5, 6]);
    expect(result).toEqual(6); // Returns the new length
  });

  it('should handle empty source array', () => {
    const target = ['a', 'b'];
    const source: string[] = [];
    const result = pushAll(target, source);

    expect(target).toEqual(['a', 'b']);
    expect(result).toEqual(2); // Returns unchanged length
  });

  it('should handle empty target array', () => {
    const target: number[] = [];
    const source = [1, 2, 3];
    const result = pushAll(target, source);

    expect(target).toEqual([1, 2, 3]);
    expect(result).toEqual(3);
  });

  it('should work with generator/iterable', () => {
    const target = [1, 2];

    // Generator function
    function* numberGenerator() {
      yield 3;
      yield 4;
      yield 5;
    }

    const result = pushAll(target, numberGenerator());

    expect(target).toEqual([1, 2, 3, 4, 5]);
    expect(result).toEqual(5);
  });

  it('should work with Set as source', () => {
    const target = ['a'];
    const source = new Set(['b', 'c', 'd']);
    const result = pushAll(target, source);

    expect(target).toEqual(['a', 'b', 'c', 'd']);
    expect(result).toEqual(4);
  });

  it('should work with Map values as source', () => {
    const target = [1];
    const map = new Map([['key1', 2], ['key2', 3]]);
    const result = pushAll(target, map.values());

    expect(target).toEqual([1, 2, 3]);
    expect(result).toEqual(3);
  });

  it('should return the new length of the target array', () => {
    const target = [1, 2, 3];
    const source = [4, 5];
    const result = pushAll(target, source);

    expect(result).toEqual(target.length);
    expect(result).toEqual(5);
  });

  it('should handle various data types', () => {
    const target = [1, 'string', true];
    const source = [null, undefined, { key: 'value' }];
    const result = pushAll<any>(target, source);

    expect(target).toEqual([1, 'string', true, null, undefined, { key: 'value' }]);
    expect(result).toEqual(6);
  });

  it('should work with string as iterable', () => {
    const target = ['a'];
    const source = 'bcd'; // String is iterable (yields characters)
    const result = pushAll(target, source);

    expect(target).toEqual(['a', 'b', 'c', 'd']);
    expect(result).toEqual(4);
  });

  it('should handle both empty target and source', () => {
    const target: number[] = [];
    const source: number[] = [];
    const result = pushAll(target, source);

    expect(target).toEqual([]);
    expect(result).toEqual(0);
  });

  it('should handle same target and source', () => {
    const arr = [1, 2, 3];
    const result = pushAll(arr, arr);

    expect(arr).toEqual([1, 2, 3, 1, 2, 3]);
    expect(result).toEqual(6);
  });
});

describe('Array utilities: unshiftAll', () => {
  it('should unshift all elements from a normal array', () => {
    const target = [1, 2, 3];
    const source = [4, 5, 6];
    const result = unshiftAll(target, source);

    expect(target).toEqual([4, 5, 6, 1, 2, 3]);
    expect(result).toEqual(6); // Returns the new length
  });

  it('should handle empty source array', () => {
    const target = ['a', 'b'];
    const source: string[] = [];
    const result = unshiftAll(target, source);

    expect(target).toEqual(['a', 'b']);
    expect(result).toEqual(2); // Returns unchanged length
  });

  it('should handle empty target array', () => {
    const target: number[] = [];
    const source = [1, 2, 3];
    const result = unshiftAll(target, source);

    expect(target).toEqual([1, 2, 3]);
    expect(result).toEqual(3);
  });

  it('should handle both empty target and source', () => {
    const target: number[] = [];
    const source: number[] = [];
    const result = unshiftAll(target, source);

    expect(target).toEqual([]);
    expect(result).toEqual(0);
  });

  it('should handle same target and source', () => {
    const arr = [1, 2, 3];
    const result = unshiftAll(arr, arr);

    expect(arr).toEqual([1, 2, 3, 1, 2, 3]);
    expect(result).toEqual(6);
  });

  it('should preserve order of source elements', () => {
    const target = ['d', 'e', 'f'];
    const source = ['a', 'b', 'c'];
    const result = unshiftAll(target, source);

    // Order: first element of source should be at index 0
    expect(target).toEqual(['a', 'b', 'c', 'd', 'e', 'f']);
    expect(result).toEqual(6);
  });

  it('should return the new length of the target array', () => {
    const target = [1, 2, 3];
    const source = [4, 5];
    const result = unshiftAll(target, source);

    expect(result).toEqual(target.length);
    expect(result).toEqual(5);
  });

  it('should handle various data types', () => {
    const target = [1, 'string', true];
    const source = [null, undefined, { key: 'value' }];
    const result = unshiftAll<any>(target, source);

    expect(target).toEqual([null, undefined, { key: 'value' }, 1, 'string', true]);
    expect(result).toEqual(6);
  });

  it('should handle single element arrays', () => {
    const target = [2];
    const source = [1];
    const result = unshiftAll(target, source);

    expect(target).toEqual([1, 2]);
    expect(result).toEqual(2);
  });

  it('should maintain reference integrity of objects', () => {
    const obj1 = { id: 1 };
    const obj2 = { id: 2 };
    const obj3 = { id: 3 };
    const target = [obj2, obj3];
    const source = [obj1];
    const result = unshiftAll(target, source);

    expect(target).toEqual([obj1, obj2, obj3]);
    expect(target[0]).toBe(obj1); // Same reference
    expect(target[1]).toBe(obj2);
    expect(target[2]).toBe(obj3);
    expect(result).toEqual(3);
  });
});
