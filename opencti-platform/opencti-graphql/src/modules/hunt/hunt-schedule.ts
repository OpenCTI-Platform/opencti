import { HUNT_SCHEDULE_MANUAL, HUNT_SCHEDULE_STANDING } from './hunt-types';

// Standard 5 fields cron expressions evaluated in UTC: minute hour day-of-month month day-of-week
const MACROS: Record<string, string> = {
  '@yearly': '0 0 1 1 *',
  '@annually': '0 0 1 1 *',
  '@monthly': '0 0 1 * *',
  '@weekly': '0 0 * * 0',
  '@daily': '0 0 * * *',
  '@midnight': '0 0 * * *',
  '@hourly': '0 * * * *',
};
const MONTH_NAMES = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
const DAY_NAMES = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
// A schedule that fires repeats within 8 years: February 29th skips the century years that are not leap years
// (2096 to 2104), every other day of the calendar comes back within a year
const MAX_SEARCH_DAYS = 366 * 8;

interface FieldSpec {
  min: number;
  max: number;
  names?: string[];
  namesOffset?: number;
}
const FIELDS: FieldSpec[] = [
  { min: 0, max: 59 }, // minute
  { min: 0, max: 23 }, // hour
  { min: 1, max: 31 }, // day of month
  { min: 1, max: 12, names: MONTH_NAMES, namesOffset: 1 }, // month
  { min: 0, max: 7, names: DAY_NAMES, namesOffset: 0 }, // day of week, 0 and 7 are Sunday
];

export interface ParsedCron {
  minutes: Set<number>;
  hours: Set<number>;
  daysOfMonth: Set<number>;
  months: Set<number>;
  daysOfWeek: Set<number>;
  dayOfMonthRestricted: boolean;
  dayOfWeekRestricted: boolean;
}

const parseValue = (raw: string, spec: FieldSpec): number => {
  const upper = raw.toUpperCase();
  if (spec.names) {
    const nameIndex = spec.names.indexOf(upper);
    if (nameIndex >= 0) {
      return nameIndex + (spec.namesOffset ?? 0);
    }
  }
  if (!/^\d+$/.test(raw)) {
    throw new Error(`invalid value "${raw}"`);
  }
  const value = Number(raw);
  if (value < spec.min || value > spec.max) {
    throw new Error(`value ${value} out of range ${spec.min}-${spec.max}`);
  }
  return value;
};

const parseField = (field: string, spec: FieldSpec): { values: Set<number>; restricted: boolean } => {
  const values = new Set<number>();
  const restricted = field !== '*' && field !== '?';
  field.split(',').forEach((part) => {
    if (part.length === 0) {
      throw new Error('empty list element');
    }
    const [rangePart, stepPart, ...rest] = part.split('/');
    if (rest.length > 0) {
      throw new Error(`invalid step in "${part}"`);
    }
    let step = 1;
    if (stepPart !== undefined) {
      if (!/^\d+$/.test(stepPart) || Number(stepPart) === 0) {
        throw new Error(`invalid step in "${part}"`);
      }
      step = Number(stepPart);
    }
    let start: number;
    let end: number;
    if (rangePart === '*' || rangePart === '?') {
      start = spec.min;
      end = spec.max;
    } else if (rangePart.includes('-')) {
      const [startRaw, endRaw, ...extra] = rangePart.split('-');
      if (extra.length > 0) {
        throw new Error(`invalid range "${rangePart}"`);
      }
      start = parseValue(startRaw, spec);
      end = parseValue(endRaw, spec);
      if (start > end) {
        throw new Error(`invalid range "${rangePart}"`);
      }
    } else {
      start = parseValue(rangePart, spec);
      end = stepPart !== undefined ? spec.max : start;
    }
    for (let value = start; value <= end; value += step) {
      values.add(value);
    }
  });
  return { values, restricted };
};

export const parseCron = (expression: string): ParsedCron => {
  const normalized = MACROS[expression.trim().toLowerCase()] ?? expression.trim();
  const parts = normalized.split(/\s+/);
  if (parts.length !== 5) {
    throw new Error('a cron expression has 5 fields: minute hour day-of-month month day-of-week');
  }
  const parsed = parts.map((part, index) => {
    try {
      return parseField(part, FIELDS[index]);
    } catch (error) {
      throw new Error(`field ${index + 1}: ${(error as Error).message}`, { cause: error });
    }
  });
  const daysOfWeek = new Set(Array.from(parsed[4].values).map((day) => day % 7));
  return {
    minutes: parsed[0].values,
    hours: parsed[1].values,
    daysOfMonth: parsed[2].values,
    months: parsed[3].values,
    daysOfWeek,
    dayOfMonthRestricted: parsed[2].restricted,
    dayOfWeekRestricted: parsed[4].restricted,
  };
};

const isDayMatching = (cron: ParsedCron, date: Date) => {
  if (!cron.months.has(date.getUTCMonth() + 1)) {
    return false;
  }
  const domMatch = cron.daysOfMonth.has(date.getUTCDate());
  const dowMatch = cron.daysOfWeek.has(date.getUTCDay());
  // Standard cron semantics: when both day fields are restricted, either one matching is enough
  if (cron.dayOfMonthRestricted && cron.dayOfWeekRestricted) {
    return domMatch || dowMatch;
  }
  if (cron.dayOfMonthRestricted) {
    return domMatch;
  }
  if (cron.dayOfWeekRestricted) {
    return dowMatch;
  }
  return true;
};

/**
 * Next occurrence strictly after the given date (minute precision, UTC), or null when the
 * expression never fires (for example February 30th).
 */
export const nextCronOccurrence = (cron: ParsedCron, after: Date): Date | null => {
  const sortedHours = Array.from(cron.hours).sort((a, b) => a - b);
  const sortedMinutes = Array.from(cron.minutes).sort((a, b) => a - b);
  const start = new Date(after.getTime());
  start.setUTCSeconds(0, 0);
  start.setUTCMinutes(start.getUTCMinutes() + 1);
  const day = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate()));
  for (let dayIndex = 0; dayIndex < MAX_SEARCH_DAYS; dayIndex += 1) {
    if (isDayMatching(cron, day)) {
      const isStartDay = dayIndex === 0;
      for (let h = 0; h < sortedHours.length; h += 1) {
        const hour = sortedHours[h];
        if (!isStartDay || hour >= start.getUTCHours()) {
          for (let m = 0; m < sortedMinutes.length; m += 1) {
            const minute = sortedMinutes[m];
            if (!isStartDay || hour > start.getUTCHours() || minute >= start.getUTCMinutes()) {
              return new Date(Date.UTC(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate(), hour, minute));
            }
          }
        }
      }
    }
    day.setUTCDate(day.getUTCDate() + 1);
  }
  return null;
};

// The Gregorian calendar repeats every 400 years, day of week included
const CALENDAR_CYCLE_DAYS = 146097;

/**
 * Smallest number of days between two matching days over a full calendar cycle, null when fewer than two days match.
 */
const shortestMatchingDayGap = (cron: ParsedCron): number | null => {
  const day = new Date(Date.UTC(2000, 0, 1));
  let previous: number | null = null;
  let shortest: number | null = null;
  for (let index = 0; index < CALENDAR_CYCLE_DAYS; index += 1) {
    if (isDayMatching(cron, day)) {
      if (previous !== null) {
        shortest = shortest === null ? index - previous : Math.min(shortest, index - previous);
        if (shortest === 1) {
          return 1;
        }
      }
      previous = index;
    }
    day.setUTCDate(day.getUTCDate() + 1);
  }
  return shortest;
};

/**
 * Shortest interval in minutes between two occurrences of a cron expression, over its whole recurrence: between two
 * times of a day (from the hours and minutes), and from the last time of a matching day to the first time of the next
 * matching day. Null when the expression fires at most once.
 */
export const cronShortestIntervalMinutes = (cron: ParsedCron): number | null => {
  const hours = Array.from(cron.hours).sort((a, b) => a - b);
  const minutes = Array.from(cron.minutes).sort((a, b) => a - b);
  const times = hours.flatMap((hour) => minutes.map((minute) => hour * 60 + minute));
  if (times.length === 0) {
    return null;
  }
  let shortest = Number.POSITIVE_INFINITY;
  for (let index = 1; index < times.length; index += 1) {
    shortest = Math.min(shortest, times[index] - times[index - 1]);
  }
  // Across midnight: only computed when it can be the shortest, the days loop covers a whole calendar cycle
  const acrossMidnight = 24 * 60 - times[times.length - 1] + times[0];
  if (acrossMidnight < shortest) {
    const dayGap = shortestMatchingDayGap(cron);
    if (dayGap !== null) {
      shortest = Math.min(shortest, (dayGap - 1) * 24 * 60 + acrossMidnight);
    }
  }
  return Number.isFinite(shortest) ? shortest : null;
};

export const isCronSchedule = (schedule: string | null | undefined): boolean => {
  return !!schedule && schedule !== HUNT_SCHEDULE_MANUAL && schedule !== HUNT_SCHEDULE_STANDING;
};

export interface ScheduleValidation {
  valid: boolean;
  error?: string;
}

/**
 * Validates a hunt schedule: manual, standing or a cron expression firing no more often than
 * the minimum interval (the budget guard of the hunt manager).
 */
export const validateHuntSchedule = (schedule: string, minIntervalMinutes: number): ScheduleValidation => {
  if (schedule === HUNT_SCHEDULE_MANUAL || schedule === HUNT_SCHEDULE_STANDING) {
    return { valid: true };
  }
  let cron: ParsedCron;
  try {
    cron = parseCron(schedule);
  } catch (error) {
    return { valid: false, error: `Invalid cron expression: ${(error as Error).message}` };
  }
  if (!nextCronOccurrence(cron, new Date(Date.UTC(2024, 0, 1)))) {
    return { valid: false, error: 'The cron expression never fires' };
  }
  const shortest = cronShortestIntervalMinutes(cron);
  if (shortest !== null && shortest < minIntervalMinutes) {
    return { valid: false, error: `The schedule must not fire more than once every ${minIntervalMinutes} minutes` };
  }
  return { valid: true };
};

export const computeNextRunAt = (schedule: string | null | undefined, after: Date): Date | null => {
  if (!schedule || !isCronSchedule(schedule)) {
    return null;
  }
  try {
    return nextCronOccurrence(parseCron(schedule), after);
  } catch {
    return null;
  }
};
