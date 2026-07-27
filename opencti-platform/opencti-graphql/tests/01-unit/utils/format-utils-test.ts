import { describe, expect, it } from 'vitest';
import { buildPeriodFromDates, checkScore, computeRangeIntersection } from '../../../src/utils/format';

describe('computeRangeIntersection tests', () => {
  it('should return the overlapping window when the two ranges intersect', () => {
    const a = buildPeriodFromDates('2020-01-01T00:00:00.000Z', '2020-06-01T00:00:00.000Z');
    const b = buildPeriodFromDates('2020-03-01T00:00:00.000Z', '2020-09-01T00:00:00.000Z');
    const result = computeRangeIntersection(a, b);
    expect(result.start).toEqual('2020-03-01T00:00:00.000Z');
    expect(result.end).toEqual('2020-06-01T00:00:00.000Z');
  });

  it('should span both ranges (min start, max end) when they do not intersect', () => {
    // a ends AFTER b: the max end must be a.end, not b.end.
    const a = buildPeriodFromDates('2020-01-01T00:00:00.000Z', '2020-06-01T00:00:00.000Z');
    const b = buildPeriodFromDates('2019-01-01T00:00:00.000Z', '2019-03-01T00:00:00.000Z');
    const result = computeRangeIntersection(a, b);
    expect(result.start).toEqual('2019-01-01T00:00:00.000Z');
    expect(result.end).toEqual('2020-06-01T00:00:00.000Z');
  });
});

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
