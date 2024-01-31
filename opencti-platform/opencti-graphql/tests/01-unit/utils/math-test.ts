import { describe, expect, it } from 'vitest';
import { cropNumber } from '../../../src/utils/math';

describe('Math utilities: cropNumber', () => {
  it('should crop value with various min/max inputs', () => {
    expect(cropNumber(50, { min: 10, max: 100 })).toEqual(50);
    expect(cropNumber(50, { min: 60, max: 100 })).toEqual(60);
    expect(cropNumber(50, { min: 10, max: 30 })).toEqual(30);

    expect(cropNumber(50, { min: 10 })).toEqual(50);
    expect(cropNumber(50, { min: 60 })).toEqual(60);

    expect(cropNumber(50, { max: 60 })).toEqual(50);
    expect(cropNumber(50, { max: 30 })).toEqual(30);

    expect(cropNumber(50, { })).toEqual(50);

    expect(() => cropNumber(50, { min: 100, max: 10 })).toThrowError('Incorrect inputs to cropNumber, min cannot be greater than max');
  });
});
