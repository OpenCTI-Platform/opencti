import { describe, expect, it } from 'vitest';
import { pushAll } from '../../../src/utils/arrayUtil';

describe('Array utilities: pushAll', () => {
  it('should push all elements from a normal array', () => {
    const target: number[] = [1, 2, 3];
    const source = [4, 5, 6];
    const result = pushAll(target, source);
    
    expect(target).toEqual([1, 2, 3, 4, 5, 6]);
    expect(result).toEqual(6); // Returns the new length
  });

  it('should handle empty source array', () => {
    const target: string[] = ['a', 'b'];
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
    const target: number[] = [1, 2];
    
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
    const target: string[] = ['a'];
    const source = new Set(['b', 'c', 'd']);
    const result = pushAll(target, source);
    
    expect(target).toEqual(['a', 'b', 'c', 'd']);
    expect(result).toEqual(4);
  });

  it('should work with Map values as source', () => {
    const target: number[] = [1];
    const map = new Map([['key1', 2], ['key2', 3]]);
    const result = pushAll(target, map.values());
    
    expect(target).toEqual([1, 2, 3]);
    expect(result).toEqual(3);
  });

  it('should return the new length of the target array', () => {
    const target: number[] = [1, 2, 3];
    const source = [4, 5];
    const result = pushAll(target, source);
    
    expect(result).toEqual(target.length);
    expect(result).toEqual(5);
  });

  it('should handle various data types', () => {
    const target: any[] = [1, 'string', true];
    const source = [null, undefined, { key: 'value' }];
    const result = pushAll(target, source);
    
    expect(target).toEqual([1, 'string', true, null, undefined, { key: 'value' }]);
    expect(result).toEqual(6);
  });

  it('should work with string as iterable', () => {
    const target: string[] = ['a'];
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
});
