import { describe, expect, it } from 'vitest';
import {
  buildDate,
  dateFiltersValueForDisplay,
  dateFormat,
  dayEndDate,
  daysBetweenDates,
  dayStartDate,
  formatDate,
  formatSeconds,
  formatUptime,
  jsDate,
  minutesBefore,
  minutesBetweenDates,
  parse,
  secondsBetweenDates,
  streamEventIdToDate,
  stringFormatMinutes,
  timestamp,
  yearFormat,
} from './Time';

describe('Time utils', () => {
  describe('dateFiltersValueForDisplay', () => {
    it('should convert a date filter value to a date value for display', () => {
      expect(dateFiltersValueForDisplay('2025-10-02T22:00:00.000Z', 'lt')).toEqual('2025-10-02T22:00:00.000Z');
      expect(dateFiltersValueForDisplay('2025-10-02T22:00:00.000Z', 'lte')).toEqual(new Date('2025-10-01T22:00:00.000Z'));
      expect(dateFiltersValueForDisplay('2025-10-02T22:00:00.000Z', 'gte')).toEqual('2025-10-02T22:00:00.000Z');
      expect(dateFiltersValueForDisplay('2025-10-02T22:00:00.000Z', 'gt')).toEqual(new Date('2025-10-01T22:00:00.000Z'));
    });
  });

  describe('formatSeconds', () => {
    it('should format seconds into hh:MM:ss string', () => {
      expect(formatSeconds(0)).toBe('00');
      expect(formatSeconds(5)).toBe('05');
      expect(formatSeconds(60)).toBe('01:00');
      expect(formatSeconds(61)).toBe('01:01');
      expect(formatSeconds(3661)).toBe('01:01:01');
      expect(formatSeconds(7322)).toBe('02:02:02');
    });
  });

  describe('formatUptime', () => {
    it('should format uptime in seconds into a human-readable string', () => {
      const t = (s: string) => s;
      expect(formatUptime(null, t)).toBe('Not available');
      expect(formatUptime(undefined, t)).toBe('Not available');
      expect(formatUptime(45, t)).toBe('45 seconds');
      expect(formatUptime(1, t)).toBe('1 second');
      expect(formatUptime(60, t)).toBe('1 minute');
      expect(formatUptime(3661, t)).toBe('1 hour, 1 minute');
      expect(formatUptime(90061, t)).toBe('1 day, 1 hour, 1 minute');
      expect(formatUptime(180122, t)).toBe('2 days, 2 hours, 2 minutes');
    });
  });

  describe('buildDate', () => {
    it('should return a Date object or null', () => {
      expect(buildDate('2024-06-15')).toEqual(new Date('2024-06-15'));
      expect(buildDate(null)).toBeNull();
      expect(buildDate(undefined)).toBeNull();
    });
  });

  describe('parse', () => {
    it('should return a Date object from a date input', () => {
      const result = parse('2024-01-15T10:00:00.000Z');
      expect(result instanceof Date).toBe(true);
      expect(isNaN(result.getTime())).toBe(false);
      expect(result.getUTCFullYear()).toBe(2024);
      expect(result.getUTCMonth()).toBe(0); // January = 0
      expect(result.getUTCDate()).toBe(15);
    });
  });

  describe('formatDate', () => {
    it('should return an ISO string or null', () => {
      expect(formatDate('2024-06-15T10:00:00.000Z')).toContain('2024-06-15');
      expect(formatDate(null)).toBeNull();
      expect(formatDate(undefined)).toBeNull();
    });
  });

  describe('dayStartDate', () => {
    it('should return start of day', () => {
      const result = dayStartDate('2024-06-15T14:30:00.000Z');
      expect(result.getHours()).toBe(0);
      expect(result.getMinutes()).toBe(0);
      expect(result.getSeconds()).toBe(0);
    });
  });

  describe('dayEndDate', () => {
    it('should return end of day', () => {
      const result = dayEndDate('2024-06-15T14:30:00.000Z');
      expect(result.getHours()).toBe(23);
      expect(result.getMinutes()).toBe(59);
      expect(result.getSeconds()).toBe(59);
    });
  });

  describe('minutesBefore', () => {
    it('should return a date string N minutes before a given date', () => {
      const result = minutesBefore(30, '2024-06-15T10:00:00.000Z');
      expect(result).toContain('2024-06-15');
      expect(result).toContain('09:30');
    });
  });

  describe('yearFormat', () => {
    it('should return the year as a string', () => {
      expect(yearFormat('2024-06-15')).toBe('2024');
      expect(yearFormat('-')).toBe('');
    });
  });

  describe('dateFormat', () => {
    it('should format a date with default or specific format', () => {
      expect(dateFormat('2024-06-15T10:00:00.000Z')).toBe('2024-06-15');
      expect(dateFormat('2024-06-15T10:00:00.000Z', 'yyyy')).toBe('2024');
      expect(dateFormat(null)).toBeNull();
    });
  });

  describe('timestamp', () => {
    it('should return unix timestamp or undefined', () => {
      expect(timestamp('2024-01-01T00:00:00.000Z')).toBe(1704067200);
      expect(timestamp(null)).toBeUndefined();
      expect(timestamp(undefined)).toBeUndefined();
    });
  });

  describe('jsDate', () => {
    it('should return a JS Date object', () => {
      const result = jsDate('2024-06-15T10:00:00.000Z');
      expect(result).toBeInstanceOf(Date);
      expect(result.getFullYear()).toBe(2024);
    });
  });

  describe('minutesBetweenDates', () => {
    it('should return the number of minutes between two dates', () => {
      expect(minutesBetweenDates('2024-01-01T10:00:00Z', '2024-01-01T10:30:00Z')).toBe(31);
    });
  });

  describe('secondsBetweenDates', () => {
    it('should return the number of seconds between two dates', () => {
      expect(secondsBetweenDates('2024-01-01T10:00:00Z', '2024-01-01T10:00:30Z')).toBe(31);
    });
  });

  describe('daysBetweenDates', () => {
    it('should return the number of days between two dates', () => {
      expect(daysBetweenDates('2024-01-01', '2024-01-10')).toBe(10);
    });
  });

  describe('stringFormatMinutes', () => {
    it('should format minutes into a human-readable string', () => {
      const t = (s: string) => s;
      expect(stringFormatMinutes(3065, t)).toBe('2 days 3 hours 5 minutes');
    });
  });

  describe('streamEventIdToDate', () => {
    it('should parse a stream event ID into an ISO date string', () => {
      // Stream event ID format: timestamp-sequence
      const ts = new Date('2024-06-15T10:00:00.000Z').getTime();
      const result = streamEventIdToDate(`${ts}-0`);
      expect(typeof result).toBe('string');
      expect(result).toContain('2024-06-15');
    });
  });
});
