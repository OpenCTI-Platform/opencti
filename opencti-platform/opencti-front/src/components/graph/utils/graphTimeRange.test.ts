import { describe, expect, it } from 'vitest';
import { countTimeRangeFilters, isOutsideTimeRange } from './graphTimeRange';

const interval: [Date, Date] = [new Date('2024-01-10T00:00:00Z'), new Date('2024-01-20T00:00:00Z')];
const minutesAfter = (date: Date, minutes: number) => new Date(date.getTime() + minutes * 60_000);

describe('isOutsideTimeRange', () => {
  it('is true before the start and after the end', () => {
    expect(isOutsideTimeRange(new Date('2024-01-09T23:59:59Z'), interval)).toBe(true);
    expect(isOutsideTimeRange(new Date('2024-01-20T00:00:01Z'), interval)).toBe(true);
  });

  it('is false inside the range and on both bounds', () => {
    expect(isOutsideTimeRange(new Date('2024-01-15T00:00:00Z'), interval)).toBe(false);
    expect(isOutsideTimeRange(interval[0], interval)).toBe(false);
    expect(isOutsideTimeRange(interval[1], interval)).toBe(false);
  });

  it('is never true for an undated element', () => {
    expect(isOutsideTimeRange(null, interval)).toBe(false);
    expect(isOutsideTimeRange(undefined, interval)).toBe(false);
    expect(isOutsideTimeRange(new Date(NaN), interval)).toBe(false);
  });
});

describe('countTimeRangeFilters', () => {
  it('is 0 when no range is selected', () => {
    expect(countTimeRangeFilters(interval, undefined)).toBe(0);
  });

  it('counts one filter per end moved more than 20 minutes', () => {
    expect(countTimeRangeFilters(interval, [minutesAfter(interval[0], 21), interval[1]])).toBe(1);
    expect(countTimeRangeFilters(interval, [interval[0], minutesAfter(interval[1], -21)])).toBe(1);
    expect(countTimeRangeFilters(interval, [minutesAfter(interval[0], 21), minutesAfter(interval[1], -21)])).toBe(2);
  });

  it('ignores an end moved by less than the margin', () => {
    expect(countTimeRangeFilters(interval, [minutesAfter(interval[0], 19), minutesAfter(interval[1], -19)])).toBe(0);
  });
});
