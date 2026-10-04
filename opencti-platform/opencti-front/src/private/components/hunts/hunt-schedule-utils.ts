// Mirrors the backend grammar (opencti-graphql/src/modules/hunt/hunt-schedule.ts): standard 5 fields
// cron expressions evaluated in UTC (minute hour day-of-month month day-of-week), plus macros.

export const HUNT_SCHEDULE_MANUAL = 'manual';
export const HUNT_SCHEDULE_STANDING = 'standing';
// Default of hunt_manager:min_schedule_interval_minutes, used until the platform value is loaded
export const HUNT_DEFAULT_MIN_SCHEDULE_INTERVAL_MINUTES = 15;

export type HuntScheduleMode = 'manual' | 'standing' | 'cron';

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
const MAX_SEARCH_DAYS = 366 * 5;
const MINUTE_IN_MS = 60 * 1000;
const WEEK_IN_MS = 7 * 24 * 60 * MINUTE_IN_MS;

interface FieldSpec {
  min: number;
  max: number;
  names?: string[];
  namesOffset?: number;
}

const FIELDS: FieldSpec[] = [
  { min: 0, max: 59 },
  { min: 0, max: 23 },
  { min: 1, max: 31 },
  { min: 1, max: 12, names: MONTH_NAMES, namesOffset: 1 },
  { min: 0, max: 7, names: DAY_NAMES, namesOffset: 0 },
];

export interface ParsedHuntCron {
  minutes: number[];
  hours: number[];
  daysOfMonth: number[];
  months: number[];
  daysOfWeek: number[];
  dayOfMonthRestricted: boolean;
  dayOfWeekRestricted: boolean;
  monthRestricted: boolean;
}

export class HuntCronError extends Error {}

export const huntScheduleMode = (schedule?: string | null): HuntScheduleMode => {
  const value = (schedule ?? '').trim();
  if (value === '' || value === HUNT_SCHEDULE_MANUAL) {
    return 'manual';
  }
  if (value === HUNT_SCHEDULE_STANDING) {
    return 'standing';
  }
  return 'cron';
};

/** Schedules other than manual run autonomously and require the Enterprise Edition. */
export const isAutonomousSchedule = (schedule?: string | null) => huntScheduleMode(schedule) !== 'manual';

const parseValue = (raw: string, spec: FieldSpec): number => {
  const upper = raw.toUpperCase();
  if (spec.names) {
    const nameIndex = spec.names.indexOf(upper);
    if (nameIndex >= 0) {
      return nameIndex + (spec.namesOffset ?? 0);
    }
  }
  if (!/^\d+$/.test(raw)) {
    throw new HuntCronError(`invalid value "${raw}"`);
  }
  const value = Number(raw);
  if (value < spec.min || value > spec.max) {
    throw new HuntCronError(`value ${value} out of range ${spec.min}-${spec.max}`);
  }
  return value;
};

const parseField = (field: string, spec: FieldSpec): { values: Set<number>; restricted: boolean } => {
  const values = new Set<number>();
  const restricted = field !== '*' && field !== '?';
  field.split(',').forEach((part) => {
    if (part.length === 0) {
      throw new HuntCronError('empty list element');
    }
    const [rangePart, stepPart, ...rest] = part.split('/');
    if (rest.length > 0) {
      throw new HuntCronError(`invalid step in "${part}"`);
    }
    let step = 1;
    if (stepPart !== undefined) {
      if (!/^\d+$/.test(stepPart) || Number(stepPart) === 0) {
        throw new HuntCronError(`invalid step in "${part}"`);
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
        throw new HuntCronError(`invalid range "${rangePart}"`);
      }
      start = parseValue(startRaw, spec);
      end = parseValue(endRaw, spec);
      if (start > end) {
        throw new HuntCronError(`invalid range "${rangePart}"`);
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

const sorted = (values: Set<number>) => Array.from(values).sort((a, b) => a - b);

export const parseHuntCron = (expression: string): ParsedHuntCron => {
  const normalized = MACROS[expression.trim().toLowerCase()] ?? expression.trim();
  const parts = normalized.split(/\s+/);
  if (parts.length !== 5) {
    throw new HuntCronError('a cron expression has 5 fields: minute hour day-of-month month day-of-week');
  }
  const parsed = parts.map((part, index) => {
    try {
      return parseField(part, FIELDS[index]);
    } catch (error) {
      throw new HuntCronError(`field ${index + 1}: ${(error as Error).message}`);
    }
  });
  return {
    minutes: sorted(parsed[0].values),
    hours: sorted(parsed[1].values),
    daysOfMonth: sorted(parsed[2].values),
    months: sorted(parsed[3].values),
    daysOfWeek: sorted(new Set(Array.from(parsed[4].values).map((day) => day % 7))),
    dayOfMonthRestricted: parsed[2].restricted,
    dayOfWeekRestricted: parsed[4].restricted,
    monthRestricted: parsed[3].restricted,
  };
};

const isDayMatching = (cron: ParsedHuntCron, date: Date) => {
  if (!cron.months.includes(date.getUTCMonth() + 1)) {
    return false;
  }
  const domMatch = cron.daysOfMonth.includes(date.getUTCDate());
  const dowMatch = cron.daysOfWeek.includes(date.getUTCDay());
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

/** Next occurrence strictly after the given date (minute precision, UTC), or null when it never fires. */
export const nextHuntCronOccurrence = (cron: ParsedHuntCron, after: Date): Date | null => {
  const start = new Date(after.getTime());
  start.setUTCSeconds(0, 0);
  start.setUTCMinutes(start.getUTCMinutes() + 1);
  const day = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate()));
  for (let dayIndex = 0; dayIndex < MAX_SEARCH_DAYS; dayIndex += 1) {
    if (isDayMatching(cron, day)) {
      const isStartDay = dayIndex === 0;
      for (const hour of cron.hours) {
        if (!isStartDay || hour >= start.getUTCHours()) {
          for (const minute of cron.minutes) {
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

export const nextHuntScheduleOccurrences = (schedule: string | null | undefined, count: number, after: Date = new Date()): Date[] => {
  if (huntScheduleMode(schedule) !== 'cron') {
    return [];
  }
  let cron: ParsedHuntCron;
  try {
    cron = parseHuntCron(schedule as string);
  } catch {
    return [];
  }
  const occurrences: Date[] = [];
  let cursor: Date | null = after;
  while (cursor && occurrences.length < count) {
    cursor = nextHuntCronOccurrence(cron, cursor);
    if (cursor) {
      occurrences.push(cursor);
    }
  }
  return occurrences;
};

export type HuntScheduleErrorCode = 'invalid' | 'never' | 'too_frequent';

export interface HuntScheduleValidation {
  valid: boolean;
  code?: HuntScheduleErrorCode;
  detail?: string;
}

/** Same rule as the backend: manual, standing, or a cron expression firing at most once every `minIntervalMinutes`. */
export const validateHuntSchedule = (
  schedule: string | null | undefined,
  minIntervalMinutes = HUNT_DEFAULT_MIN_SCHEDULE_INTERVAL_MINUTES,
): HuntScheduleValidation => {
  if (huntScheduleMode(schedule) !== 'cron') {
    return { valid: true };
  }
  let cron: ParsedHuntCron;
  try {
    cron = parseHuntCron(schedule as string);
  } catch (error) {
    return { valid: false, code: 'invalid', detail: (error as Error).message };
  }
  let previous = nextHuntCronOccurrence(cron, new Date(Date.UTC(2024, 0, 1)));
  if (!previous) {
    return { valid: false, code: 'never' };
  }
  const horizon = previous.getTime() + WEEK_IN_MS;
  while (previous && previous.getTime() < horizon) {
    const next = nextHuntCronOccurrence(cron, previous);
    if (!next) {
      break;
    }
    if ((next.getTime() - previous.getTime()) / MINUTE_IN_MS < minIntervalMinutes) {
      return { valid: false, code: 'too_frequent' };
    }
    previous = next;
  }
  return { valid: true };
};

export interface HuntScheduleDescription {
  /** i18n message key, its placeholders are given in values */
  message: string;
  values?: Record<string, string | number>;
  /** Days of the week (0 = Sunday) the schedule is restricted to, to be named by the caller */
  weekDays?: number[];
}

const pad = (value: number) => String(value).padStart(2, '0');
const isFullRange = (values: number[], min: number, max: number) => values.length === max - min + 1;

/** Uniform step of a list starting at its minimum, null when the list is not an arithmetic sequence. */
const uniformStep = (values: number[], min: number, max: number): number | null => {
  if (values.length < 2 || values[0] !== min) {
    return null;
  }
  const step = values[1] - values[0];
  const isUniform = values.every((value, index) => value === min + index * step);
  return isUniform && values[values.length - 1] + step > max ? step : null;
};

/**
 * Human readable description of a hunt schedule. Common shapes get a sentence, anything else
 * falls back to the raw expression (the caller also shows the next occurrences).
 */
export const describeHuntSchedule = (schedule: string | null | undefined): HuntScheduleDescription => {
  const mode = huntScheduleMode(schedule);
  if (mode === 'manual') {
    return { message: 'Manual, runs only when started' };
  }
  if (mode === 'standing') {
    return { message: 'Standing, runs when matching knowledge changes' };
  }
  let cron: ParsedHuntCron;
  try {
    cron = parseHuntCron(schedule as string);
  } catch {
    return { message: 'Invalid cron expression' };
  }
  const allDays = !cron.dayOfMonthRestricted && !cron.dayOfWeekRestricted && !cron.monthRestricted;
  const allHours = isFullRange(cron.hours, 0, 23);
  const minuteStep = uniformStep(cron.minutes, 0, 59);
  const hourStep = uniformStep(cron.hours, 0, 23);
  if (allDays && allHours && minuteStep === 1) {
    return { message: 'Every minute' };
  }
  if (allDays && allHours && minuteStep !== null) {
    return { message: 'Every {count} minutes', values: { count: minuteStep } };
  }
  if (allDays && allHours && cron.minutes.length === 1) {
    return { message: 'Every hour at minute {minute}', values: { minute: cron.minutes[0] } };
  }
  if (allDays && hourStep !== null && cron.minutes.length === 1) {
    return { message: 'Every {count} hours at minute {minute}', values: { count: hourStep, minute: cron.minutes[0] } };
  }
  if (cron.hours.length === 1 && cron.minutes.length === 1) {
    const time = `${pad(cron.hours[0])}:${pad(cron.minutes[0])}`;
    if (allDays) {
      return { message: 'Every day at {time} UTC', values: { time } };
    }
    if (!cron.monthRestricted && cron.dayOfWeekRestricted && !cron.dayOfMonthRestricted) {
      return { message: 'Every {days} at {time} UTC', values: { time }, weekDays: cron.daysOfWeek };
    }
    if (!cron.monthRestricted && cron.dayOfMonthRestricted && !cron.dayOfWeekRestricted) {
      return { message: 'On day {days} of every month at {time} UTC', values: { time, days: cron.daysOfMonth.join(', ') } };
    }
  }
  return { message: 'Custom schedule {expression} (UTC)', values: { expression: (schedule as string).trim() } };
};
