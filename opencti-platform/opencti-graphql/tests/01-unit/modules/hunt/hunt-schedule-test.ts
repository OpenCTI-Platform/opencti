import { describe, expect, it } from 'vitest';
import { computeNextRunAt, isCronSchedule, nextCronOccurrence, parseCron, validateHuntSchedule } from '../../../../src/modules/hunt/hunt-schedule';

const at = (iso: string) => new Date(iso);

describe('Hunt schedules', () => {
  it('should recognize cron schedules', () => {
    expect(isCronSchedule('manual')).toBe(false);
    expect(isCronSchedule('standing')).toBe(false);
    expect(isCronSchedule(null)).toBe(false);
    expect(isCronSchedule('')).toBe(false);
    expect(isCronSchedule('*/30 * * * *')).toBe(true);
  });

  it('should parse fields, ranges, steps, lists, names and macros', () => {
    const cron = parseCron('0,30 9-17/4 * JAN-MAR mon-fri');
    expect(Array.from(cron.minutes)).toEqual([0, 30]);
    expect(Array.from(cron.hours)).toEqual([9, 13, 17]);
    expect(Array.from(cron.months)).toEqual([1, 2, 3]);
    expect(Array.from(cron.daysOfWeek)).toEqual([1, 2, 3, 4, 5]);
    expect(cron.dayOfMonthRestricted).toBe(false);
    expect(cron.dayOfWeekRestricted).toBe(true);
    expect(Array.from(parseCron('@daily').hours)).toEqual([0]);
    // 7 is Sunday too
    expect(Array.from(parseCron('0 0 * * 7').daysOfWeek)).toEqual([0]);
    expect(Array.from(parseCron('5/20 * * * *').minutes)).toEqual([5, 25, 45]);
  });

  it('should refuse invalid expressions with the faulty field', () => {
    expect(() => parseCron('* * * *')).toThrow('5 fields');
    expect(() => parseCron('61 * * * *')).toThrow('field 1');
    expect(() => parseCron('* 5-2 * * *')).toThrow('field 2: invalid range');
    expect(() => parseCron('*/0 * * * *')).toThrow('invalid step');
    expect(() => parseCron('* * * FOO *')).toThrow('field 4');
    expect(() => parseCron('1,,2 * * * *')).toThrow('empty list element');
    expect(() => parseCron('1/2/3 * * * *')).toThrow('invalid step');
    expect(() => parseCron('1-2-3 * * * *')).toThrow('invalid range');
  });

  it('should compute the next occurrence in UTC, strictly after the date', () => {
    expect(nextCronOccurrence(parseCron('*/30 * * * *'), at('2026-10-03T10:00:00.000Z'))?.toISOString()).toBe('2026-10-03T10:30:00.000Z');
    expect(nextCronOccurrence(parseCron('*/30 * * * *'), at('2026-10-03T10:29:59.000Z'))?.toISOString()).toBe('2026-10-03T10:30:00.000Z');
    expect(nextCronOccurrence(parseCron('15 2 * * *'), at('2026-10-03T03:00:00.000Z'))?.toISOString()).toBe('2026-10-04T02:15:00.000Z');
    // 2026-10-03 is a Saturday: next Monday
    expect(nextCronOccurrence(parseCron('0 8 * * 1'), at('2026-10-03T12:00:00.000Z'))?.toISOString()).toBe('2026-10-05T08:00:00.000Z');
    expect(nextCronOccurrence(parseCron('0 0 29 2 *'), at('2026-10-03T00:00:00.000Z'))?.toISOString()).toBe('2028-02-29T00:00:00.000Z');
  });

  it('should use the cron semantics of both day fields', () => {
    // Day of month 1 OR Monday when both are restricted
    expect(nextCronOccurrence(parseCron('0 0 1 * 1'), at('2026-10-03T00:00:00.000Z'))?.toISOString()).toBe('2026-10-05T00:00:00.000Z');
    expect(nextCronOccurrence(parseCron('0 0 1 * *'), at('2026-10-03T00:00:00.000Z'))?.toISOString()).toBe('2026-11-01T00:00:00.000Z');
  });

  it('should never fire impossible dates', () => {
    expect(nextCronOccurrence(parseCron('0 0 30 2 *'), at('2026-10-03T00:00:00.000Z'))).toBeNull();
  });

  it('should validate schedules against the minimum interval', () => {
    expect(validateHuntSchedule('manual', 15)).toEqual({ valid: true });
    expect(validateHuntSchedule('standing', 15)).toEqual({ valid: true });
    expect(validateHuntSchedule('0 */6 * * *', 15)).toEqual({ valid: true });
    expect(validateHuntSchedule('*/5 * * * *', 15).valid).toBe(false);
    expect(validateHuntSchedule('0,5 * * * *', 15).error).toContain('15 minutes');
    expect(validateHuntSchedule('not a cron', 15).error).toContain('Invalid cron expression');
    expect(validateHuntSchedule('0 0 30 2 *', 15)).toEqual({ valid: false, error: 'The cron expression never fires' });
  });

  it('should check the minimum interval over the whole recurrence of sparse schedules', () => {
    // Two minutes apart once a month
    expect(validateHuntSchedule('0,1 0 1 * *', 15).valid).toBe(false);
    // Five minutes apart across midnight, every day or between the 31st and the 1st of the next month
    expect(validateHuntSchedule('0,55 0,23 * * *', 15).valid).toBe(false);
    expect(validateHuntSchedule('0,55 0,23 1,31 * *', 15).valid).toBe(false);
    // The same times on days never adjacent, and hours apart across midnight
    expect(validateHuntSchedule('0,55 0,23 1,15 * *', 15)).toEqual({ valid: true });
    expect(validateHuntSchedule('30 0,23 * * *', 15)).toEqual({ valid: true });
    expect(validateHuntSchedule('0 12 * * MON', 15)).toEqual({ valid: true });
  });

  it('should compute the next run date of cron schedules only', () => {
    expect(computeNextRunAt('manual', at('2026-10-03T00:00:00.000Z'))).toBeNull();
    expect(computeNextRunAt('standing', at('2026-10-03T00:00:00.000Z'))).toBeNull();
    expect(computeNextRunAt('invalid cron', at('2026-10-03T00:00:00.000Z'))).toBeNull();
    expect(computeNextRunAt('@hourly', at('2026-10-03T00:10:00.000Z'))?.toISOString()).toBe('2026-10-03T01:00:00.000Z');
  });
});
