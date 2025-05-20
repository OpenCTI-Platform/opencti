import { describe, expect, it } from 'vitest';
import { isValidScore } from '../../../src/utils/format';

describe('checkScoreValue tests', () => {
  it('should throw validationError for score > 100', () => {
    expect(() => isValidScore(110))
      .toThrowError('The score should be an integer between 0 and 100');
  });
  it('should throw validationError for score < 0', () => {
    expect(() => isValidScore(-3))
      .toThrowError('The score should be an integer between 0 and 100');
  });
  it('should throw validationError for non integer score', () => {
    expect(() => isValidScore(0.5))
      .toThrowError('The score should be an integer between 0 and 100');
  });
  it('should return true if score is an integer between 0 and 100', () => {
    const check = isValidScore(40);
    expect(check).toEqual(true);
  });
});
