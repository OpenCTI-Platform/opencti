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

// Complements the suite above: period semantics preserved when porting away from moment-range.
describe('computeRangeIntersection period semantics', () => {
  const day = (n: number) => new Date(Date.UTC(2020, 0, n)).toISOString();
  const intersection = (a: number[], b: number[]) => computeRangeIntersection(
    buildPeriodFromDates(day(a[0]), day(a[1])),
    buildPeriodFromDates(day(b[0]), day(b[1])),
  );

  it('should return the overlapping period of two crossing periods', () => {
    expect(intersection([1, 3], [2, 4])).toEqual({ start: day(2), end: day(3) });
  });
  it('should return the inner period when a period contains the other', () => {
    expect(intersection([1, 4], [2, 3])).toEqual({ start: day(2), end: day(3) });
  });
  it('should return the single instant of an instant period inside another period', () => {
    expect(intersection([1, 4], [2, 2])).toEqual({ start: day(2), end: day(2) });
  });
  it('should fallback on the enclosing period when periods do not overlap', () => {
    expect(intersection([1, 2], [3, 4])).toEqual({ start: day(1), end: day(4) });
  });
  it('should fallback on the enclosing period when periods only touch each other', () => {
    expect(intersection([1, 2], [2, 4])).toEqual({ start: day(1), end: day(4) });
  });
  it('should fallback on the enclosing period for two identical instant periods', () => {
    expect(intersection([2, 2], [2, 2])).toEqual({ start: day(2), end: day(2) });
  });
  it('should treat a period without dates as unbounded', () => {
    // A relation with no start_time / stop_time must not restrict the period it is combined with.
    const unbounded = buildPeriodFromDates(undefined, undefined);
    expect(computeRangeIntersection(buildPeriodFromDates(day(2), day(3)), unbounded))
      .toEqual({ start: day(2), end: day(3) });
    expect(computeRangeIntersection(unbounded, buildPeriodFromDates(day(2), day(3))))
      .toEqual({ start: day(2), end: day(3) });
  });
  it('should keep an instant period combined with a period without dates', () => {
    expect(computeRangeIntersection(
      buildPeriodFromDates(day(2), day(2)),
      buildPeriodFromDates(null, null),
    )).toEqual({ start: day(2), end: day(2) });
  });
});
