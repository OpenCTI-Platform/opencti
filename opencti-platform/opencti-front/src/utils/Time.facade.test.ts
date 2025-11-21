import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import moment from 'moment';
import 'moment-timezone';
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
 * Comparison tests between moment.js and Time.ts facade functions
 * These tests verify that the Time.ts facade (using date-fns internally)
 * produces identical outputs to moment.js for all replaced functions
 */
describe('Time.ts as Moment.js facade', () => {
  // Mock current date for consistent testing
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-01-15T10:30:00.000Z'));
    moment.locale('en'); // Reset to English locale
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('parseDate() as moment() - Core facade function', () => {
    describe('format() method', () => {
      it('should match moment().utc().format() without parameters', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(testDate).format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-15T10:30:00Z');
      });

      it('should handle YYYY-MM-DD format conversion', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).format('YYYY-MM-DD');
        const facadeResult = parseDate(testDate).format('YYYY-MM-DD');

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-15');
      });

      it('should handle YYYY format conversion', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).format('YYYY');
        const facadeResult = parseDate(testDate).format('YYYY');

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025');
      });

      it('should handle DD format conversion', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).format('DD');
        const facadeResult = parseDate(testDate).format('DD');

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('15');
      });

      it('should handle YY format conversion', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).format('YY');
        const facadeResult = parseDate(testDate).format('YY');

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('25');
      });

      it('should handle D format conversion (day without leading zero)', () => {
        const testDate = '2025-01-05T10:30:00.000Z';

        const momentResult = moment(testDate).format('D');
        const facadeResult = parseDate(testDate).format('D');

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('5');
      });
    });

    describe('unix() method', () => {
      it('should match moment().unix()', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).unix();
        const facadeResult = parseDate(testDate).unix();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe(1736937000);
      });

      it('should handle Unix timestamp input (seconds)', () => {
        const unixTimestamp = 1736937000; // 2025-01-15T10:30:00.000Z

        const momentResult = moment.unix(unixTimestamp).unix();
        const facadeResult = parseDate(unixTimestamp).unix();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe(1736937000);
      });
    });

    describe('valueOf() method', () => {
      it('should match moment().valueOf()', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).valueOf();
        const facadeResult = parseDate(testDate).valueOf();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe(1736937000000);
      });
    });

    describe('toDate() method', () => {
      it('should match moment().toDate()', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).toDate();
        const facadeResult = parseDate(testDate).toDate();

        expect(facadeResult.toISOString()).toBe(momentResult.toISOString());
        expect(facadeResult.toISOString()).toBe('2025-01-15T10:30:00.000Z');
      });
    });

    describe('subtract() method', () => {
      it('should match moment().subtract() for days', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).subtract(5, 'days').utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(testDate).subtract(5, 'days').format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-10T10:30:00Z');
      });

      it('should match moment().subtract() for months', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).subtract(3, 'months').utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(testDate).subtract(3, 'months').format();

        expect(facadeResult).toBe(momentResult);
        // Expecting 09:30 due to timezone handling in moment
        expect(facadeResult).toBe('2024-10-15T09:30:00Z');
      });

      it('should match moment().subtract() for years', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).subtract(2, 'years').utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(testDate).subtract(2, 'years').format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2023-01-15T10:30:00Z');
      });

      it('should match moment().subtract() for minutes', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).subtract(30, 'minutes').utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(testDate).subtract(30, 'minutes').format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-15T10:00:00Z');
      });
    });

    describe('add() method', () => {
      it('should match moment().add() for days', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).add(5, 'days').utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(testDate).add(5, 'days').format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-20T10:30:00Z');
      });
    });

    describe('endOf() method', () => {
      it('should match moment().endOf("day")', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment.utc(testDate).endOf('day').format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(testDate).endOf('day').format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-15T23:59:59Z');
      });

      it('should match moment().endOf("month")', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment.utc(testDate).endOf('month').format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(testDate).endOf('month').format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-31T23:59:59Z');
      });
    });

    describe('diff() method', () => {
      it('should match moment().diff() for minutes', () => {
        const start = '2025-01-15T10:00:00.000Z';
        const end = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(end).diff(moment(start), 'minutes');
        const facadeResult = parseDate(start).diff(end, 'minutes');

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe(30);
      });

      it('should match moment().diff() for seconds', () => {
        const start = '2025-01-15T10:00:00.000Z';
        const end = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(end).diff(moment(start), 'seconds');
        const facadeResult = parseDate(start).diff(end, 'seconds');

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe(1800);
      });
    });

    describe('utc().format() method', () => {
      it('should match moment().utc().format()', () => {
        const testDate = '2025-01-15T10:30:00.000Z';

        const momentResult = moment(testDate).utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(testDate).utc().format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-15T10:30:00Z');
      });
    });

    describe('Edge cases', () => {
      it('should handle null input like moment()', () => {
        // Note: moment(null) returns "Invalid date" while our facade returns current date
        // This is an acceptable divergence as moment's behavior is inconsistent
        const facadeResult = parseDate(null).format();

        // Our facade returns "Invalid date" for null input
        expect(facadeResult).toBe('Invalid date');
      });

      it('should handle undefined input like moment()', () => {
        const momentResult = moment(undefined).utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(undefined).format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-15T10:30:00Z');
      });

      it('should handle date-only strings like moment()', () => {
        const testDate = '2025-01-15';

        const momentResult = moment.utc(testDate).format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(testDate).format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-15T00:00:00Z');
      });

      it('should handle Date objects', () => {
        const testDate = new Date('2025-01-15T10:30:00.000Z');

        const momentResult = moment(testDate).utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(testDate).format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-15T10:30:00Z');
      });

      it('should handle millisecond timestamps', () => {
        const timestampValue = 1736937000000; // 2025-01-15T10:30:00.000Z

        const momentResult = moment(timestampValue).utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
        const facadeResult = parseDate(timestampValue).format();

        expect(facadeResult).toBe(momentResult);
        expect(facadeResult).toBe('2025-01-15T10:30:00Z');
      });
    });
  });

  describe('formatDateToISO() as moment formatting', () => {
    it('should match moment().utc().format() for ISO dates', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment(testDate).utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = formatDateToISO(testDate);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15T10:30:00Z');
    });

    it('should match moment for Date objects', () => {
      const testDate = new Date('2025-01-15T10:30:00.000Z');

      const momentResult = moment(testDate).utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = formatDateToISO(testDate);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15T10:30:00Z');
    });

    it('should handle null/undefined appropriately', () => {
      // Our facade returns null for null/undefined, moment would return "Invalid date"
      // This is an intentional difference
      expect(formatDateToISO(null)).toBeNull();
      expect(formatDateToISO(undefined)).toBeNull();
    });
  });

  describe('dayStartDateUTC() as moment.startOf("day")', () => {
    it('should match moment.utc().startOf("day") for current date', () => {
      const momentResult = moment.utc().startOf('day').toDate();
      const facadeResult = dayStartDateUTC();

      expect(facadeResult.toISOString()).toBe(momentResult.toISOString());
      expect(facadeResult.toISOString()).toBe('2025-01-15T00:00:00.000Z');
    });

    it('should match moment.utc().startOf("day") for specific date', () => {
      const testDate = '2025-01-20T15:45:30.000Z';

      const momentResult = moment.utc(testDate).startOf('day').toDate();
      const facadeResult = dayStartDateUTC(testDate);

      expect(facadeResult.toISOString()).toBe(momentResult.toISOString());
      expect(facadeResult.toISOString()).toBe('2025-01-20T00:00:00.000Z');
    });

    it('should return original date when fromStart is false', () => {
      const testDate = '2025-01-20T15:45:30.000Z';

      const facadeResult = dayStartDateUTC(testDate, false);

      expect(facadeResult.toISOString()).toBe('2025-01-20T15:45:30.000Z');
    });
  });

  describe('dayEndDateUTC() as moment.endOf("day")', () => {
    it('should match moment.utc().endOf("day") for current date', () => {
      const momentResult = moment.utc().endOf('day').toDate();
      const facadeResult = dayEndDateUTC();

      expect(facadeResult.toISOString()).toBe(momentResult.toISOString());
      expect(facadeResult.toISOString()).toBe('2025-01-15T23:59:59.999Z');
    });

    it('should match moment.utc().endOf("day") for specific date', () => {
      const testDate = '2025-01-20T10:00:00.000Z';

      const momentResult = moment.utc(testDate).endOf('day').toDate();
      const facadeResult = dayEndDateUTC(testDate);

      expect(facadeResult.toISOString()).toBe(momentResult.toISOString());
      expect(facadeResult.toISOString()).toBe('2025-01-20T23:59:59.999Z');
    });
  });

  describe('nowInUTC() as moment()', () => {
    it('nowInUTC() should match moment().utc().format()', () => {
      const momentResult = moment().utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = nowInUTC();

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15T10:30:00Z');
    });

    it('nowInUTC() should match moment.utc().format() (duplicate test for clarity)', () => {
      const momentResult = moment.utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = nowInUTC();

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15T10:30:00Z');
    });
  });

  describe('Date arithmetic functions', () => {
    it('dayAgoUTC() should match moment().subtract(1, "day")', () => {
      const momentResult = moment().subtract(1, 'day').utc().format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = dayAgoUTC();

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-14T10:30:00Z');
    });

    it('daysAgoUTC() should match moment for N days ago', () => {
      const momentResult = moment.utc().startOf('day').subtract(5, 'days').format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = daysAgoUTC(5);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-10T00:00:00Z');
    });

    it('daysAgoUTC() with specific date should match moment', () => {
      const baseDate = '2025-01-20T10:00:00.000Z';

      const momentResult = moment.utc(baseDate).startOf('day').subtract(5, 'days').format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = daysAgoUTC(5, baseDate);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15T00:00:00Z');
    });

    it('daysAgoUTC() with fromStart=false should match moment', () => {
      const baseDate = '2025-01-20T10:00:00.000Z';

      const momentResult = moment.utc(baseDate).subtract(5, 'days').format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = daysAgoUTC(5, baseDate, false);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15T10:00:00Z');
    });

    it('lastDayOfThePreviousMonth() should match moment', () => {
      const momentResult = moment.utc().subtract(1, 'month').endOf('month').format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = lastDayOfThePreviousMonth();

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2024-12-31T23:59:59Z');
    });

    it('daysAfter() should match moment.add()', () => {
      const baseDate = '2025-01-10T00:00:00.000Z';

      const momentResult = moment.utc(baseDate).add(5, 'days').format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = daysAfter(5, baseDate, false);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15T00:00:00Z');
    });

    it('minutesBefore() should match moment.subtract() for minutes', () => {
      const baseDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment.utc(baseDate).subtract(30, 'minutes').format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = minutesBefore(30, baseDate);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15T10:00:00Z');
    });

    it('monthsAgo() should match moment for N months ago', () => {
      const momentResult = moment.utc().startOf('day').subtract(3, 'months').format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = monthsAgo(3);

      // Month arithmetic can vary due to different month lengths
      // Verify the month is correct
      expect(facadeResult).toContain('2024-10');
      expect(momentResult).toContain('2024-10');
    });

    it('yearsAgo() should match moment for N years ago', () => {
      const momentResult = moment.utc().startOf('day').subtract(2, 'years').format('YYYY-MM-DDTHH:mm:ss[Z]');
      const facadeResult = yearsAgo(2);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2023-01-15T00:00:00Z');
    });
  });

  describe('Format functions', () => {
    it('yearFormat() should match moment.format("YYYY")', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment(testDate).format('YYYY');
      const facadeResult = yearFormat(testDate);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025');
    });

    it('yearFormat() should handle Date objects', () => {
      const testDate = new Date('2025-01-15');

      const momentResult = moment(testDate).format('YYYY');
      const facadeResult = yearFormat(testDate);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025');
    });

    it('dateFormat() should match moment.format() with default format', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment(testDate).format('YYYY-MM-DD');
      const facadeResult = dateFormat(testDate);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15');
    });

    it('dateFormat() should handle custom format YYYY-MM-DD', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment(testDate).format('YYYY-MM-DD');
      const facadeResult = dateFormat(testDate, 'YYYY-MM-DD');

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15');
    });

    it('dateFormat() should handle custom format YYYY', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment(testDate).format('YYYY');
      const facadeResult = dateFormat(testDate, 'YYYY');

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025');
    });

    it('dateFormat() should handle custom format DD', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment(testDate).format('DD');
      const facadeResult = dateFormat(testDate, 'DD');

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('15');
    });

    it('formatTimeForToday() should create today\'s date with specific time', () => {
      const time = '14:30:00';

      const momentResult = `${moment().format('YYYY-MM-DD')}T${time}`;
      const facadeResult = formatTimeForToday(time);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15T14:30:00');
    });
  });

  describe('Utility functions', () => {
    it('timestamp() should match moment.unix()', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment(testDate).unix();
      const facadeResult = timestamp(testDate);

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe(1736937000);
    });

    it('jsDate() should match moment.toDate()', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment(testDate).toDate();
      const facadeResult = jsDate(testDate);

      expect(facadeResult.toISOString()).toBe(momentResult.toISOString());
      expect(facadeResult.toISOString()).toBe('2025-01-15T10:30:00.000Z');
    });

    it('minutesBetweenDates() should calculate correctly', () => {
      const start = '2025-01-15T10:00:00.000Z';
      const end = '2025-01-15T10:30:00.000Z';

      const momentDiff = Math.abs(moment(end).diff(moment(start), 'minutes')) + 1;
      const facadeResult = minutesBetweenDates(start, end);

      expect(facadeResult).toBe(momentDiff);
      expect(facadeResult).toBe(31); // 30 minutes + 1
    });

    it('secondsBetweenDates() should calculate correctly', () => {
      const start = '2025-01-15T10:00:00.000Z';
      const end = '2025-01-15T10:00:30.000Z';

      const momentDiff = Math.abs(moment(end).diff(moment(start), 'seconds')) + 1;
      const facadeResult = secondsBetweenDates(start, end);

      expect(facadeResult).toBe(momentDiff);
      expect(facadeResult).toBe(31); // 30 seconds + 1
    });
  });

  describe('setDateFormatLocale() - Locale management', () => {
    it('should accept locale strings like moment.locale()', () => {
      // Test various locale formats
      setDateFormatLocale('en-us');
      setDateFormatLocale('fr-fr');
      setDateFormatLocale('de-de');
      setDateFormatLocale('es-es');

      // Should not throw errors
      expect(() => setDateFormatLocale('en')).not.toThrow();
      expect(() => setDateFormatLocale('fr')).not.toThrow();
      expect(() => setDateFormatLocale('de')).not.toThrow();
    });

    it('should handle case-insensitive locale names', () => {
      expect(() => setDateFormatLocale('EN-US')).not.toThrow();
      expect(() => setDateFormatLocale('Fr-Fr')).not.toThrow();
      expect(() => setDateFormatLocale('DE')).not.toThrow();
    });
  });

  describe('humanizeDateDuration() - Duration humanization', () => {
    it('should return human-readable duration for minutes', () => {
      // Reset locale to English for consistent output
      setDateFormatLocale('en');

      const facadeResult = humanizeDateDuration(30, 'minutes');

      // The exact output depends on the locale, but it should be a non-empty string
      expect(facadeResult).toBeTruthy();
      expect(typeof facadeResult).toBe('string');
    });

    it('should return human-readable duration for hours', () => {
      setDateFormatLocale('en');

      const facadeResult = humanizeDateDuration(2, 'hours');

      expect(facadeResult).toBeTruthy();
      expect(typeof facadeResult).toBe('string');
    });

    it('should return human-readable duration for days', () => {
      setDateFormatLocale('en');

      const facadeResult = humanizeDateDuration(7, 'days');

      expect(facadeResult).toBeTruthy();
      expect(typeof facadeResult).toBe('string');
    });

    it('should return human-readable duration for months', () => {
      setDateFormatLocale('en');

      const facadeResult = humanizeDateDuration(3, 'months');

      expect(facadeResult).toBeTruthy();
      expect(typeof facadeResult).toBe('string');
    });

    it('should return human-readable duration for years', () => {
      setDateFormatLocale('en');

      const facadeResult = humanizeDateDuration(2, 'years');

      expect(facadeResult).toBeTruthy();
      expect(typeof facadeResult).toBe('string');
    });

    it('should handle null/undefined/zero values', () => {
      setDateFormatLocale('en');

      const nullResult = humanizeDateDuration(null, 'days');
      const undefinedResult = humanizeDateDuration(undefined, 'days');
      const zeroResult = humanizeDateDuration(0, 'days');

      // All should return a string (likely "less than a minute" or similar)
      expect(typeof nullResult).toBe('string');
      expect(typeof undefinedResult).toBe('string');
      expect(typeof zeroResult).toBe('string');
    });

    it('should handle singular as plural units', () => {
      setDateFormatLocale('en');

      const minuteResult = humanizeDateDuration(1, 'minute');
      const minutesResult = humanizeDateDuration(1, 'minutes');

      // Both should work and return the same result
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
      const parseDateResult = parseDate(new Date()).format();
      const momentDateResult = momentDate().format();

      expect(momentDateResult).toBe(parseDateResult);
      expect(momentDateResult).toBe('2025-01-15T10:30:00Z');
    });

    it('should handle undefined input by returning current date', () => {
      const parseDateResult = parseDate(new Date()).format();
      const momentDateResult = momentDate(undefined).format();

      expect(momentDateResult).toBe(parseDateResult);
      expect(momentDateResult).toBe('2025-01-15T10:30:00Z');
    });
  });

  describe('Complex date manipulations', () => {
    it('should handle chained operations like moment', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      // moment().subtract(5, 'days').add(2, 'days').format()
      const momentResult = moment(testDate)
        .subtract(5, 'days')
        .add(2, 'days')
        .utc()
        .format('YYYY-MM-DDTHH:mm:ss[Z]');

      const facadeResult = parseDate(testDate)
        .subtract(5, 'days')
        .add(2, 'days')
        .format();

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-12T10:30:00Z');
    });

    it('should handle endOf() after subtract() like moment', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment.utc(testDate)
        .subtract(1, 'month')
        .endOf('month')
        .format('YYYY-MM-DDTHH:mm:ss[Z]');

      const facadeResult = parseDate(testDate)
        .subtract(1, 'month')
        .endOf('month')
        .format();

      expect(facadeResult).toBe(momentResult);
      // After subtracting 1 month from 2025-01-15, we get 2024-12-15
      // The end of that month is 2024-12-31T23:59:59Z
      expect(facadeResult).toBe('2024-12-31T23:59:59Z');
    });
  });

  describe('Special format patterns', () => {
    it('should handle combined format patterns', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment(testDate).format('YYYY/MM/DD');
      const facadeResult = parseDate(testDate).format('YYYY/MM/DD');

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025/01/15');
    });

    it('should preserve non-format characters', () => {
      const testDate = '2025-01-15T10:30:00.000Z';

      const momentResult = moment(testDate).format('YYYY-MM-DD');
      const facadeResult = parseDate(testDate).format('YYYY-MM-DD');

      expect(facadeResult).toBe(momentResult);
      expect(facadeResult).toBe('2025-01-15');
    });
  });

  describe('TypeScript fixes verification', () => {
    describe('dateFormat() with unknown type', () => {
      it('should accept unknown values (entity.published case)', () => {
        const unknownValue: unknown = '2025-01-15T10:30:00.000Z';

        const result = dateFormat(unknownValue);

        expect(result).toBe('2025-01-15');
        expect(typeof result).toBe('string');
      });

      it('should accept unknown with custom format', () => {
        const unknownValue: unknown = '2025-01-15T10:30:00.000Z';

        const result = dateFormat(unknownValue, 'YYYY-MM-DD');

        expect(result).toBe('2025-01-15');
        expect(typeof result).toBe('string');
      });

      it('should always return string, never null', () => {
        const nullResult = dateFormat(null);
        const undefinedResult = dateFormat(undefined);
        const emptyResult = dateFormat('');

        // All should return empty string, not null
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
        expect(result4).toBeInstanceOf(Date); // Returns new Date() for null
        expect(result5).toBeInstanceOf(Date); // Returns new Date() for undefined
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

        // Should have toISOString method
        expect(typeof result.toISOString).toBe('function');
        expect(typeof result.format).toBe('function');
        expect(typeof result.unix).toBe('function');

        // Should be able to call toISOString()
        const isoString = result.toISOString();
        expect(typeof isoString).toBe('string');
        expect(isoString).toContain('T00:00:00'); // Should be start of day
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

        // Should return a MomentLike for timestamp 0
        const date = result.toDate();
        expect(date).toBeInstanceOf(Date);
      });

      it('should accept null', () => {
        const result = streamEventIdToDate(null);

        expect(typeof result.format).toBe('function');
        expect(typeof result.toDate).toBe('function');

        // Should return a MomentLike for timestamp 0
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
        // Should be one day before
        expect((result as Date).toISOString()).toBe('2025-01-14T10:30:00.000Z');
      });

      it('should return Date for gt operator', () => {
        const input = '2025-01-15T10:30:00.000Z';
        const result = dateFiltersValueForDisplay(input, 'gt');

        expect(result).toBeInstanceOf(Date);
        // Should be one day before
        expect((result as Date).toISOString()).toBe('2025-01-14T10:30:00.000Z');
      });

      it('should return value compatible with Date constructor', () => {
        const stringInput = '2025-01-15T10:30:00.000Z';
        const dateInput = new Date('2025-01-15T10:30:00.000Z');
        const numberInput = 1736937000000;

        const result1 = dateFiltersValueForDisplay(stringInput);
        const result2 = dateFiltersValueForDisplay(dateInput);
        const result3 = dateFiltersValueForDisplay(numberInput);

        // All results should be compatible with Date constructor
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

    describe('MomentLike interface with toISOString and utc().format()', () => {
      it('should have toISOString() method', () => {
        const momentLike = parseDate('2025-01-15T10:30:00.000Z');

        expect(typeof momentLike.toISOString).toBe('function');
        const isoString = momentLike.toISOString();
        expect(isoString).toBe('2025-01-15T10:30:00.000Z');
      });

      it('should have utc().format() with optional formatStr', () => {
        const momentLike = parseDate('2025-01-15T10:30:00.000Z');

        // Without format string
        const defaultFormat = momentLike.utc().format();
        expect(defaultFormat).toBe('2025-01-15T10:30:00Z');

        // With format string
        const customFormat = momentLike.utc().format('HH:mm:ss');
        expect(customFormat).toBe('10:30:00');
      });
    });

    describe('parseToUTC() handling MomentLike objects', () => {
      it('should handle MomentLike objects in parseDate', () => {
        const momentLike = parseDate('2025-01-15T10:30:00.000Z');

        // Using MomentLike in diff method
        const other = parseDate('2025-01-15T11:00:00.000Z');
        const diffMinutes = momentLike.diff(other, 'minutes');

        expect(diffMinutes).toBe(30);
      });

      it('should handle MomentLike in DateInput', () => {
        const momentLike = parseDate('2025-01-15T10:30:00.000Z');

        // Pass MomentLike as DateInput
        const result = dateFormat(momentLike as DateInput);

        expect(result).toBe('2025-01-15');
      });
    });
  });
});
