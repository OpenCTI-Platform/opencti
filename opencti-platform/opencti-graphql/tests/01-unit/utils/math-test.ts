import { describe, expect, it } from 'vitest';
import { cropNumber } from '../../../src/utils/math';
import { FunctionalError } from '../../../src/config/errors';

describe('Math utilities: cropNumber', () => {
  it('should crop value with various min/max inputs', () => {
    expect(cropNumber(50, 10, 100)).toEqual(50);
    expect(cropNumber(50, 60, 100)).toEqual(60);
    expect(cropNumber(50, 10, 30)).toEqual(30);

    expect(() => cropNumber(50, 100, 10))
      .toThrow(FunctionalError('min cannot be greater than max'));
    expect(() => cropNumber(NaN, 10, 80))
      .toThrow(FunctionalError('Cannot process non-finite input'));
    expect(() => cropNumber(50, NaN, 80))
      .toThrow(FunctionalError('Cannot process non-finite input'));
    expect(() => cropNumber(50, 10, NaN))
      .toThrow(FunctionalError('Cannot process non-finite input'));
  });
});
