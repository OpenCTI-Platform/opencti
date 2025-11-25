import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import {
  setDateFormatLocale,
  parseDate,
  formatDateToISO,
  dayStartDateUTC,
  dayEndDateUTC,
  nowInUTC,
  dayAgoUTC,
  daysAgoUTC,
  lastDayOfThePreviousMonth,
  daysAfter,
  minutesBefore,
  monthsAgo,
  yearsAgo,
  yearFormat,
  dateFormat,
  formatTimeForToday,
  timestamp,
  jsDate,
  minutesBetweenDates,
  secondsBetweenDates,
  humanizeDateDuration,
  momentDate,
  buildDate,
  DateInput,
  dayStartDate,
  streamEventIdToDate,
  dateFiltersValueForDisplay,
} from './Time';

/**
 * Tests for Time.ts facade functions (date-fns based implementation)
 * These tests verify that the Time.ts facade functions work correctly
 * after the migration from moment.js to date-fns
 */
describe('Time.ts facade functions', () => {
  // Mock current date for consistent testing
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-15T10:30:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('parseDate() - Core facade function', () => {
    describe('format() method', () => {
      it('should format dates in ISO format without parameters', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).format();

        expect(result).toBe('2025-01-15T10:30:00Z');
      });

      it('should handle YYYY-MM-DD format conversion', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).format('YYYY-MM-DD');

        expect(result).toBe('2025-01-15');
      });

      it('should handle YYYY format conversion', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).format('YYYY');

        expect(result).toBe('2025');
      });

      it('should handle DD format conversion', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).format('DD');

        expect(result).toBe('15');
      });

      it('should handle YY format conversion', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).format('YY');

        expect(result).toBe('25');
      });

      it('should handle D format conversion (day without leading zero)', () => {
        const testDate = '2025-01-05T10:30:00.000Z';

        const result = parseDate(testDate).format('D');

        expect(result).toBe('5');
      });
    });

    describe('unix() method', () => {
      it('should return Unix timestamp in seconds', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).unix();

        expect(result).toBe(1736937000);
      });

      it('should handle Unix timestamp input (seconds)', () => {
        const unixTimestamp = 1736937000; // 2025-01-15T10:30:00.000Z

        const result = parseDate(unixTimestamp).unix();

        expect(result).toBe(1736937000);
      });
    });

    describe('valueOf() method', () => {
      it('should return timestamp in milliseconds', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).valueOf();

        expect(result).toBe(1736937000000);
      });
    });

    describe('toDate() method', () => {
      it('should convert to JavaScript Date object', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).toDate();

        expect(result.toISOString()).toBe('2025-01-15T10:30:00.000Z');
      });
    });

    describe('subtract() method', () => {
      it('should subtract days correctly', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).subtract(5, 'days').format();

        expect(result).toBe('2025-01-10T10:30:00Z');
      });

      it('should subtract months correctly', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).subtract(3, 'months').format();

        expect(result).toBe('2024-10-15T10:30:00Z');
      });

      it('should subtract years correctly', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).subtract(2, 'years').format();

        expect(result).toBe('2023-01-15T10:30:00Z');
      });

      it('should subtract minutes correctly', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).subtract(30, 'minutes').format();

        expect(result).toBe('2025-01-15T10:00:00Z');
      });
    });

    describe('add() method', () => {
      it('should add days correctly', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).add(5, 'days').format();

        expect(result).toBe('2025-01-20T10:30:00Z');
      });
    });

    describe('endOf() method', () => {
      it('should get end of day correctly', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).endOf('day').format();

        expect(result).toBe('2025-01-15T23:59:59Z');
      });

      it('should get end of month correctly', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).endOf('month').format();

        expect(result).toBe('2025-01-31T23:59:59Z');
      });
    });

    describe('diff() method', () => {
      it('should calculate difference in minutes', () => {
        const start = '2025-01-15T10:00:00.000Z';
        const end = '2025-01-15T10:30:00.000Z';

        const result = parseDate(start).diff(end, 'minutes');

        expect(result).toBe(30);
      });

      it('should calculate difference in seconds', () => {
        const start = '2025-01-15T10:00:00.000Z';
        const end = '2025-01-15T10:30:00.000Z';

        const result = parseDate(start).diff(end, 'seconds');

        expect(result).toBe(1800);
      });
    });

    describe('utc().format() method', () => {
      it('should format in UTC', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const result = parseDate(testDate).utc().format();

        expect(result).toBe('2025-01-15T10:30:00Z');
      });
    });

    describe('Edge cases', () => {
      it('should handle null input', () => {
        const result = parseDate(null).format();

        expect(result).toBe('Invalid date');
      });

      it('should handle undefined input by using current date', () => {
        const result = parseDate(undefined).format();

        expect(result).toBe('2025-01-15T10:30:00Z');
      });

      it('should handle date-only strings', () => {
        const testDate = '2025-01-15';

        const result = parseDate(testDate).format();

        expect(result).toBe('2025-01-15T00:00:00Z');
      });

      it('should handle Date objects', () => {
        const testDate = new Date('2025-01-15T10:30:00.000Z');

        const result = parseDate(testDate).format();

        expect(result).toBe('2025-01-15T10:30:00Z');
      });

      it('should handle millisecond timestamps', () => {
        const timestampValue = 1736937000000; // 2025-01-15T10:30:00.000Z

        const result = parseDate(timestampValue).format();

        expect(result).toBe('2025-01-15T10:30:00Z');
      });
    });
  });

  describe('formatDateToISO()', () => {
    it('should format dates to ISO format', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = formatDateToISO(testDate);

      expect(result).toBe('2025-01-15T10:30:00Z');
    });

    it('should handle Date objects', () => {
      const testDate = new Date('2025-01-15T10:30:00.000Z');

      const result = formatDateToISO(testDate);

      expect(result).toBe('2025-01-15T10:30:00Z');
    });

    it('should handle null/undefined appropriately', () => {
      expect(formatDateToISO(null)).toBeNull();
      expect(formatDateToISO(undefined)).toBeNull();
    });
  });

  describe('dayStartDateUTC()', () => {
    it('should return start of day in UTC for current date', () => {
      const result = dayStartDateUTC();

      expect(result.toISOString()).toBe('2025-01-15T00:00:00.000Z');
    });

    it('should return start of day in UTC for specific date', () => {
      const testDate = '2025-01-20T15:45:30.000Z';

      const result = dayStartDateUTC(testDate);

      expect(result.toISOString()).toBe('2025-01-20T00:00:00.000Z');
    });

    it('should return original date when fromStart is false', () => {
      const testDate = '2025-01-20T15:45:30.000Z';

      const result = dayStartDateUTC(testDate, false);

      expect(result.toISOString()).toBe('2025-01-20T15:45:30.000Z');
    });
  });

  describe('dayEndDateUTC()', () => {
    it('should return end of day in UTC for current date', () => {
      const result = dayEndDateUTC();

      expect(result.toISOString()).toBe('2025-01-15T23:59:59.999Z');
    });

    it('should return end of day in UTC for specific date', () => {
      const testDate = '2025-01-20T10:00:00.000Z';

      const result = dayEndDateUTC(testDate);

      expect(result.toISOString()).toBe('2025-01-20T23:59:59.999Z');
    });
  });

  describe('nowInUTC()', () => {
    it('should return current time in UTC format', () => {
      const result = nowInUTC();

      expect(result).toBe('2025-01-15T10:30:00Z');
    });
  });

  describe('Date arithmetic functions', () => {
    it('dayAgoUTC() should return one day ago', () => {
      const result = dayAgoUTC();

      expect(result).toBe('2025-01-14T10:30:00Z');
    });

    it('daysAgoUTC() should return N days ago from start of day', () => {
      const result = daysAgoUTC(5);

      expect(result).toBe('2025-01-10T00:00:00Z');
    });

    it('daysAgoUTC() with specific date should calculate from that date', () => {
      const baseDate = '2025-01-20T10:00:00.000Z';

      const result = daysAgoUTC(5, baseDate);

      expect(result).toBe('2025-01-15T00:00:00Z');
    });

    it('daysAgoUTC() with fromStart=false should preserve time', () => {
      const baseDate = '2025-01-20T10:00:00.000Z';

      const result = daysAgoUTC(5, baseDate, false);

      expect(result).toBe('2025-01-15T10:00:00Z');
    });

    it('lastDayOfThePreviousMonth() should return last day of previous month', () => {
      const result = lastDayOfThePreviousMonth();

      expect(result).toBe('2024-12-31T23:59:59Z');
    });

    it('daysAfter() should add days to date', () => {
      const baseDate = '2025-01-10T00:00:00.000Z';

      const result = daysAfter(5, baseDate, false);

      expect(result).toBe('2025-01-15T00:00:00Z');
    });

    it('minutesBefore() should subtract minutes', () => {
      const baseDate = '2025-01-15T10:30:00.000Z';

      const result = minutesBefore(30, baseDate);

      expect(result).toBe('2025-01-15T10:00:00Z');
    });

    it('monthsAgo() should return N months ago', () => {
      const result = monthsAgo(3);

      expect(result).toContain('2024-10');
    });

    it('yearsAgo() should return N years ago', () => {
      const result = yearsAgo(2);

      expect(result).toBe('2023-01-15T00:00:00Z');
    });
  });

  describe('Format functions', () => {
    it('yearFormat() should return year in YYYY format', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = yearFormat(testDate);

      expect(result).toBe('2025');
    });

    it('yearFormat() should handle Date objects', () => {
      const testDate = new Date('2025-01-15');

      const result = yearFormat(testDate);

      expect(result).toBe('2025');
    });

    it('dateFormat() should format with default format', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = dateFormat(testDate);

      expect(result).toBe('2025-01-15');
    });

    it('dateFormat() should handle custom format YYYY-MM-DD', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = dateFormat(testDate, 'YYYY-MM-DD');

      expect(result).toBe('2025-01-15');
    });

    it('dateFormat() should handle custom format YYYY', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = dateFormat(testDate, 'YYYY');

      expect(result).toBe('2025');
    });

    it('dateFormat() should handle custom format DD', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = dateFormat(testDate, 'DD');

      expect(result).toBe('15');
    });

    it('formatTimeForToday() should create today\'s date with specific time', () => {
      const time = '14:30:00';

      const result = formatTimeForToday(time);

      expect(result).toBe('2025-01-15T14:30:00');
    });
  });

  describe('Utility functions', () => {
    it('timestamp() should return Unix timestamp', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = timestamp(testDate);

      expect(result).toBe(1736937000);
    });

    it('jsDate() should return JavaScript Date object', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = jsDate(testDate);

      expect(result.toISOString()).toBe('2025-01-15T10:30:00.000Z');
    });

    it('minutesBetweenDates() should calculate correctly', () => {
      const start = '2025-01-15T10:00:00.000Z';
      const end = '2025-01-15T10:30:00.000Z';

      const result = minutesBetweenDates(start, end);

      expect(result).toBe(31); // 30 minutes + 1
    });

    it('secondsBetweenDates() should calculate correctly', () => {
      const start = '2025-01-15T10:00:00.000Z';
      const end = '2025-01-15T10:00:30.000Z';

      const result = secondsBetweenDates(start, end);

      expect(result).toBe(31); // 30 seconds + 1
    });
  });

  describe('setDateFormatLocale() - Locale management', () => {
    it('should accept locale strings', () => {
      expect(() => setDateFormatLocale('en-us')).not.toThrow();
      expect(() => setDateFormatLocale('fr-fr')).not.toThrow();
      expect(() => setDateFormatLocale('de-de')).not.toThrow();
      expect(() => setDateFormatLocale('es-es')).not.toThrow();
    });

    it('should handle case-insensitive locale names', () => {
      expect(() => setDateFormatLocale('EN-US')).not.toThrow();
      expect(() => setDateFormatLocale('Fr-Fr')).not.toThrow();
      expect(() => setDateFormatLocale('DE')).not.toThrow();
    });
  });

  describe('humanizeDateDuration() - Duration humanization', () => {
    beforeEach(() => {
      setDateFormatLocale('en');
    });

    it('should return human-readable duration for minutes', () => {
      const result = humanizeDateDuration(30, 'minutes');

      expect(result).toBeTruthy();
      expect(typeof result).toBe('string');
    });

    it('should return human-readable duration for hours', () => {
      const result = humanizeDateDuration(2, 'hours');

      expect(result).toBeTruthy();
      expect(typeof result).toBe('string');
    });

    it('should return human-readable duration for days', () => {
      const result = humanizeDateDuration(7, 'days');

      expect(result).toBeTruthy();
      expect(typeof result).toBe('string');
    });

    it('should return human-readable duration for months', () => {
      const result = humanizeDateDuration(3, 'months');

      expect(result).toBeTruthy();
      expect(typeof result).toBe('string');
    });

    it('should return human-readable duration for years', () => {
      const result = humanizeDateDuration(2, 'years');

      expect(result).toBeTruthy();
      expect(typeof result).toBe('string');
    });

    it('should handle null/undefined/zero values', () => {
      const nullResult = humanizeDateDuration(null, 'days');
      const undefinedResult = humanizeDateDuration(undefined, 'days');
      const zeroResult = humanizeDateDuration(0, 'days');

      expect(typeof nullResult).toBe('string');
      expect(typeof undefinedResult).toBe('string');
      expect(typeof zeroResult).toBe('string');
    });

    it('should handle singular as plural units', () => {
      const minuteResult = humanizeDateDuration(1, 'minute');
      const minutesResult = humanizeDateDuration(1, 'minutes');

      expect(minuteResult).toBe(minutesResult);
    });
  });

  describe('momentDate() - Deprecated facade function', () => {
    it('should match parseDate() for date input', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const parseDateResult = parseDate(testDate).format();
      const momentDateResult = momentDate(testDate).format();

      expect(momentDateResult).toBe(parseDateResult);
      expect(momentDateResult).toBe('2025-01-15T10:30:00Z');
    });

    it('should return current date when no input provided', () => {
      const result = momentDate().format();

      expect(result).toBe('2025-01-15T10:30:00Z');
    });

    it('should handle undefined input by returning current date', () => {
      const result = momentDate(undefined).format();

      expect(result).toBe('2025-01-15T10:30:00Z');
    });
  });

  describe('Complex date manipulations', () => {
    it('should handle chained operations', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = parseDate(testDate)
        .subtract(5, 'days')
        .add(2, 'days')
        .format();

      expect(result).toBe('2025-01-12T10:30:00Z');
    });

    it('should handle endOf() after subtract()', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = parseDate(testDate)
        .subtract(1, 'month')
        .endOf('month')
        .format();

      expect(result).toBe('2024-12-31T23:59:59Z');
    });
  });

  describe('Special format patterns', () => {
    it('should handle combined format patterns', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = parseDate(testDate).format('YYYY/MM/DD');

      expect(result).toBe('2025/01/15');
    });

    it('should preserve non-format characters', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const result = parseDate(testDate).format('YYYY-MM-DD');

      expect(result).toBe('2025-01-15');
    });
  });

  describe('TypeScript type compatibility', () => {
    describe('dateFormat() with unknown type', () => {
      it('should accept unknown values', () => {
        const unknownValue: unknown = '2025-01-15T10:30:00.000Z';

        const result = dateFormat(unknownValue);

        expect(result).toBe('2025-01-15');
        expect(typeof result).toBe('string');
      });

      it('should accept unknown with custom format', () => {
        const unknownValue: unknown = '2025-01-15T10:30:00.000Z';

        const result = dateFormat(unknownValue, 'YYYY-MM-DD');

        expect(result).toBe('2025-01-15');
      });

      it('should always return string, never null', () => {
        const nullResult = dateFormat(null);
        const undefinedResult = dateFormat(undefined);
        const emptyResult = dateFormat('');

        expect(nullResult).toBe('');
        expect(undefinedResult).toBe('');
        expect(emptyResult).toBe('');
        expect(typeof nullResult).toBe('string');
        expect(typeof undefinedResult).toBe('string');
        expect(typeof emptyResult).toBe('string');
      });

      it('should handle special case "-" by returning empty string', () => {
        const result = dateFormat('-');

        expect(result).toBe('');
        expect(typeof result).toBe('string');
      });
    });

    describe('buildDate() with DateInput type', () => {
      it('should accept various DateInput types', () => {
        const stringDate: DateInput = '2025-01-15T10:30:00.000Z';
        const dateObject: DateInput = new Date('2025-01-15T10:30:00.000Z');
        const numberDate: DateInput = 1736937000000;
        const nullDate: DateInput = null;
        const undefinedDate: DateInput = undefined;
        const objectWithValue: DateInput = { value: '2025-01-15T10:30:00.000Z' };

        const result1 = buildDate(stringDate);
        const result2 = buildDate(dateObject);
        const result3 = buildDate(numberDate);
        const result4 = buildDate(nullDate);
        const result5 = buildDate(undefinedDate);
        const result6 = buildDate(objectWithValue);

        expect(result1).toBeInstanceOf(Date);
        expect(result2).toBeInstanceOf(Date);
        expect(result3).toBeInstanceOf(Date);
        expect(result4).toBeInstanceOf(Date);
        expect(result5).toBeInstanceOf(Date);
        expect(result6).toBeInstanceOf(Date);
      });

      it('should handle unknown type in DateInput', () => {
        const unknownValue: unknown = '2025-01-15T10:30:00.000Z';

        const result = buildDate(unknownValue as DateInput);

        expect(result).toBeInstanceOf(Date);
        expect(result.toISOString()).toBe('2025-01-15T10:30:00.000Z');
      });
    });

    describe('dayStartDate() overloads', () => {
      it('should return MomentLike when called without arguments', () => {
        const result = dayStartDate();

        expect(typeof result.toISOString).toBe('function');
        expect(typeof result.format).toBe('function');
        expect(typeof result.unix).toBe('function');

        const isoString = result.toISOString();
        expect(typeof isoString).toBe('string');
        expect(isoString).toContain('T00:00:00');
      });

      it('should return Date when called with arguments', () => {
        const result = dayStartDate('2025-01-15T10:30:00.000Z');

        expect(result).toBeInstanceOf(Date);
        expect(result.toISOString()).toBe('2025-01-15T00:00:00.000Z');
      });

      it('should return Date when called with date and fromStart', () => {
        const result = dayStartDate('2025-01-15T10:30:00.000Z', false);

        expect(result).toBeInstanceOf(Date);
        expect(result.toISOString()).toBe('2025-01-15T10:30:00.000Z');
      });
    });

    describe('streamEventIdToDate() with undefined/null', () => {
      it('should accept undefined', () => {
        const result = streamEventIdToDate(undefined);

        expect(typeof result.format).toBe('function');
        expect(typeof result.toDate).toBe('function');

        const date = result.toDate();
        expect(date).toBeInstanceOf(Date);
      });

      it('should accept null', () => {
        const result = streamEventIdToDate(null);

        expect(typeof result.format).toBe('function');
        expect(typeof result.toDate).toBe('function');

        const date = result.toDate();
        expect(date).toBeInstanceOf(Date);
      });

      it('should handle valid stream event ID', () => {
        const streamId = '1736937000000-0';
        const result = streamEventIdToDate(streamId);

        expect(typeof result.format).toBe('function');
        const formatted = result.format('YYYY-MM-DD');
        expect(formatted).toBe('2025-01-15');
      });
    });

    describe('dateFiltersValueForDisplay() return type', () => {
      it('should return Date for lte operator', () => {
        const input = '2025-01-15T10:30:00.000Z';
        const result = dateFiltersValueForDisplay(input, 'lte');

        expect(result).toBeInstanceOf(Date);
        expect((result as Date).toISOString()).toBe('2025-01-14T10:30:00.000Z');
      });

      it('should return Date for gt operator', () => {
        const input = '2025-01-15T10:30:00.000Z';
        const result = dateFiltersValueForDisplay(input, 'gt');

        expect(result).toBeInstanceOf(Date);
        expect((result as Date).toISOString()).toBe('2025-01-14T10:30:00.000Z');
      });

      it('should return value compatible with Date constructor', () => {
        const stringInput = '2025-01-15T10:30:00.000Z';
        const dateInput = new Date('2025-01-15T10:30:00.000Z');
        const numberInput = 1736937000000;

        const result1 = dateFiltersValueForDisplay(stringInput);
        const result2 = dateFiltersValueForDisplay(dateInput);
        const result3 = dateFiltersValueForDisplay(numberInput);

        const date1 = new Date(result1 as string | number | Date);
        const date2 = new Date(result2 as string | number | Date);
        const date3 = new Date(result3 as string | number | Date);

        expect(date1).toBeInstanceOf(Date);
        expect(date2).toBeInstanceOf(Date);
        expect(date3).toBeInstanceOf(Date);
      });

      it('should handle null/undefined by returning Date', () => {
        const result1 = dateFiltersValueForDisplay(null);
        const result2 = dateFiltersValueForDisplay(undefined);

        expect(result1).toBeInstanceOf(Date);
        expect(result2).toBeInstanceOf(Date);
      });

      it('should handle complex objects by converting to Date', () => {
        const complexObject = { value: '2025-01-15T10:30:00.000Z' };
        const result = dateFiltersValueForDisplay(complexObject);

        expect(result).toBeInstanceOf(Date);
        expect((result as Date).toISOString()).toBe('2025-01-15T10:30:00.000Z');
      });
    });

    describe('MomentLike interface', () => {
      it('should have toISOString() method', () => {
        const momentLike = parseDate('2025-01-15T10:30:00.000Z');

        expect(typeof momentLike.toISOString).toBe('function');
        const isoString = momentLike.toISOString();
        expect(isoString).toBe('2025-01-15T10:30:00.000Z');
      });

      it('should have utc().format() with optional formatStr', () => {
        const momentLike = parseDate('2025-01-15T10:30:00.000Z');

        const defaultFormat = momentLike.utc().format();
        expect(defaultFormat).toBe('2025-01-15T10:30:00Z');

        const customFormat = momentLike.utc().format('HH:mm:ss');
        expect(customFormat).toBe('10:30:00');
      });
    });

    describe('MomentLike handling in parseDate', () => {
      it('should handle MomentLike objects in diff method', () => {
        const momentLike = parseDate('2025-01-15T10:30:00.000Z');
        const other = parseDate('2025-01-15T11:00:00.000Z');

        const diffMinutes = momentLike.diff(other, 'minutes');

        expect(diffMinutes).toBe(30);
      });

      it('should handle MomentLike in DateInput', () => {
        const momentLike = parseDate('2025-01-15T10:30:00.000Z');

        const result = dateFormat(momentLike as DateInput);

        expect(result).toBe('2025-01-15');
      });
    });
  });
});
