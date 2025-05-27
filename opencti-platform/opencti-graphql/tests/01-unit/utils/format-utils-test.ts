import { describe, expect, it } from 'vitest';
import { checkScore } from '../../../src/utils/format';

describe('checkScoreValue tests', () => {
  it('should throw validationError for score > 100', () => {
    expect(() => checkScore(110))
      .toThrowError('The score should be an integer between 0 and 100');
  });
  it('should throw validationError for score < 0', () => {
    expect(() => checkScore(-3))
      .toThrowError('The score should be an integer between 0 and 100');
  });
  it('should throw validationError for non integer score', () => {
    expect(() => checkScore(0.5))
      .toThrowError('The score should be an integer between 0 and 100');
  });
  it('should return true if score is undefined', () => {
    const check = checkScore(undefined);
    expect(check).toEqual(true);
  });
  it('should return true if score is an integer between 0 and 100', () => {
    const check = checkScore(40);
    expect(check).toEqual(true);
  });
  it('should return true if score is correct string', () => {
    const check = checkScore('40');
    expect(check).toEqual(true);
  });
  it('should return true if score is correct string', () => {
    const check = checkScore('0');
    expect(check).toEqual(true);
  });
  it('should throw validationError for non integer score', () => {
    expect(() => checkScore('0.5'))
      .toThrowError('The score should be an integer between 0 and 100');
  });
});
