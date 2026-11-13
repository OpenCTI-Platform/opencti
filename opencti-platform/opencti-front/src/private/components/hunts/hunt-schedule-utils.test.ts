import { describe, expect, it } from 'vitest';
import { describeHuntSchedule, huntScheduleMode, isAutonomousSchedule, nextHuntScheduleOccurrences, parseHuntCron, validateHuntSchedule } from './hunt-schedule-utils';

describe('Hunt schedule utils', () => {
  describe('huntScheduleMode()', () => {
    it('should read manual, standing and cron schedules', () => {
      expect(huntScheduleMode(undefined)).toEqual('manual');
      expect(huntScheduleMode('')).toEqual('manual');
      expect(huntScheduleMode('manual')).toEqual('manual');
      expect(huntScheduleMode('standing')).toEqual('standing');
      expect(huntScheduleMode('*/30 * * * *')).toEqual('cron');
      expect(huntScheduleMode('@daily')).toEqual('cron');
    });

    it('should flag every schedule but manual as autonomous', () => {
      expect(isAutonomousSchedule('manual')).toBe(false);
      expect(isAutonomousSchedule('standing')).toBe(true);
      expect(isAutonomousSchedule('0 6 * * 1')).toBe(true);
    });
  });

  describe('parseHuntCron()', () => {
    it('should expand lists, ranges, steps and names', () => {
      const cron = parseHuntCron('0,30 8-10 * JAN-MAR MON,FRI');
      expect(cron.minutes).toEqual([0, 30]);
      expect(cron.hours).toEqual([8, 9, 10]);
      expect(cron.months).toEqual([1, 2, 3]);
      expect(cron.daysOfWeek).toEqual([1, 5]);
      expect(cron.dayOfWeekRestricted).toBe(true);
      expect(cron.dayOfMonthRestricted).toBe(false);
    });

    it('should treat 7 as Sunday and expand macros', () => {
      expect(parseHuntCron('0 0 * * 7').daysOfWeek).toEqual([0]);
      expect(parseHuntCron('@hourly').minutes).toEqual([0]);
    });

    it('should reject malformed expressions', () => {
      expect(() => parseHuntCron('* * * *')).toThrow('5 fields');
      expect(() => parseHuntCron('61 * * * *')).toThrow('field 1');
      expect(() => parseHuntCron('*/0 * * * *')).toThrow('invalid step');
      expect(() => parseHuntCron('0 10-8 * * *')).toThrow('invalid range');
    });
  });

  describe('validateHuntSchedule()', () => {
    it('should accept manual, standing and spaced cron schedules', () => {
      expect(validateHuntSchedule('manual').valid).toBe(true);
      expect(validateHuntSchedule('standing').valid).toBe(true);
      expect(validateHuntSchedule('*/15 * * * *').valid).toBe(true);
      expect(validateHuntSchedule('0 6 * * 1-5').valid).toBe(true);
    });

    it('should reject schedules firing more often than every 15 minutes', () => {
      expect(validateHuntSchedule('*/5 * * * *')).toEqual({ valid: false, code: 'too_frequent' });
      expect(validateHuntSchedule('0,5 * * * *')).toEqual({ valid: false, code: 'too_frequent' });
    });

    it('should check the interval over the whole recurrence of sparse schedules', () => {
      expect(validateHuntSchedule('0,1 0 1 * *')).toEqual({ valid: false, code: 'too_frequent' });
      expect(validateHuntSchedule('0,55 0,23 * * *')).toEqual({ valid: false, code: 'too_frequent' });
      expect(validateHuntSchedule('0,55 0,23 1,31 * *')).toEqual({ valid: false, code: 'too_frequent' });
      expect(validateHuntSchedule('0,55 0,23 1,15 * *').valid).toBe(true);
      expect(validateHuntSchedule('30 0,23 * * *').valid).toBe(true);
    });

    it('should reject invalid and never firing expressions', () => {
      expect(validateHuntSchedule('every day').code).toEqual('invalid');
      expect(validateHuntSchedule(`${Array.from({ length: 100 }, (_, index) => index % 60).join(',')} * * * *`))
        .toEqual({ valid: false, code: 'invalid', detail: 'a cron expression is at most 256 characters' });
      expect(validateHuntSchedule('0 0 30 2 *')).toEqual({ valid: false, code: 'never' });
    });
  });

  describe('nextHuntScheduleOccurrences()', () => {
    it('should compute the next UTC occurrences strictly after the reference date', () => {
      const after = new Date(Date.UTC(2026, 9, 3, 10, 7, 30));
      const occurrences = nextHuntScheduleOccurrences('*/30 * * * *', 3, after);
      expect(occurrences.map((date) => date.toISOString())).toEqual([
        '2026-10-03T10:30:00.000Z',
        '2026-10-03T11:00:00.000Z',
        '2026-10-03T11:30:00.000Z',
      ]);
    });

    it('should honour week days', () => {
      // 2026-10-03 is a Saturday, the next Monday is 2026-10-05
      const after = new Date(Date.UTC(2026, 9, 3, 12, 0));
      expect(nextHuntScheduleOccurrences('0 6 * * MON', 1, after)[0].toISOString()).toEqual('2026-10-05T06:00:00.000Z');
    });

    it('should return nothing for manual, standing and invalid schedules', () => {
      expect(nextHuntScheduleOccurrences('manual', 3)).toEqual([]);
      expect(nextHuntScheduleOccurrences('standing', 3)).toEqual([]);
      expect(nextHuntScheduleOccurrences('not a cron', 3)).toEqual([]);
    });
  });

  describe('describeHuntSchedule()', () => {
    it('should describe manual and standing schedules', () => {
      expect(describeHuntSchedule('manual').message).toEqual('Manual, runs only when started');
      expect(describeHuntSchedule('standing').message).toEqual('Standing, runs when matching knowledge changes');
    });

    it('should describe common cron shapes', () => {
      expect(describeHuntSchedule('*/30 * * * *')).toEqual({ message: 'Every {count} minutes', values: { count: 30 } });
      expect(describeHuntSchedule('15 * * * *')).toEqual({ message: 'Every hour at minute {minute}', values: { minute: 15 } });
      expect(describeHuntSchedule('0 */6 * * *')).toEqual({ message: 'Every {count} hours at minute {minute}', values: { count: 6, minute: 0 } });
      expect(describeHuntSchedule('@daily')).toEqual({ message: 'Every day at {time} UTC', values: { time: '00:00' } });
      expect(describeHuntSchedule('30 7 * * 1,3')).toEqual({ message: 'Every {days} at {time} UTC', values: { time: '07:30' }, weekDays: [1, 3] });
      expect(describeHuntSchedule('0 3 1,15 * *')).toEqual({ message: 'On day {days} of every month at {time} UTC', values: { time: '03:00', days: '1, 15' } });
    });

    it('should fall back to the raw expression for irregular schedules', () => {
      expect(describeHuntSchedule('5,20 1,13 * 6 *')).toEqual({ message: 'Custom schedule {expression} (UTC)', values: { expression: '5,20 1,13 * 6 *' } });
      expect(describeHuntSchedule('nope').message).toEqual('Invalid cron expression');
    });
  });
});
