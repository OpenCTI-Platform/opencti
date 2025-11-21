import {
  parseISO,
  format,
  subDays,
  subMonths,
  subYears,
  addDays,
  addMonths,
  addYears,
  subMinutes,
  getUnixTime,
  differenceInMinutes,
  differenceInSeconds,
  endOfMonth,
  isValid,
  formatDistanceToNow,
} from 'date-fns';
import { formatInTimeZone } from 'date-fns-tz';
import { enUS, fr, de, es, it, ja, ko, zhCN, ru } from 'date-fns/locale';
import type { Locale } from 'date-fns';

// Type definitions
export type DateInput = string | Date | number | null | undefined | { value: string } | MomentLike | unknown;
type TranslationFunction = (key: string) => string;
type FilterOperator = 'lt' | 'lte' | 'gt' | 'gte' | string;

// Internal duration unit type for consistent handling
type DurationUnit = 'minute' | 'hour' | 'day' | 'month' | 'year';

// Constants
const defaultDateFormat = 'yyyy-MM-dd';
const yearDateFormat = 'yyyy';
const momentCompatibleFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";
const FROM_START = 0;
const UNTIL_END = 100000000000000;

// ========== HELPER FUNCTIONS ==========

const createUTCDate = (date: Date, hours = 0, minutes = 0, seconds = 0, milliseconds = 0): Date => {
  return new Date(Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate(),
    hours,
    minutes,
    seconds,
    milliseconds,
  ));
};

const startOfDayUTC = (date: Date): Date => createUTCDate(date, 0, 0, 0, 0);
const endOfDayUTC = (date: Date): Date => createUTCDate(date, 23, 59, 59, 999);

const convertMomentFormatToDateFns = (formatString: string): string => {
  return formatString
    .replace(/YYYY/g, 'yyyy')
    .replace(/YY/g, 'yy')
    .replace(/MM/g, 'MM')
    .replace(/DD/g, 'dd')
    .replace(/D/g, 'd')
    .replace(/HH/g, 'HH')
    .replace(/mm/g, 'mm')
    .replace(/ss/g, 'ss')
    .replace(/SSS/g, 'SSS');
};

// Normalize duration unit string to standard DurationUnit
const normalizeDurationUnit = (unit: string): DurationUnit => {
  const normalized = unit.toLowerCase().replace(/s$/, ''); // Remove trailing 's'
  switch (normalized) {
    case 'minute':
      return 'minute';
    case 'hour':
      return 'hour';
    case 'day':
      return 'day';
    case 'month':
      return 'month';
    case 'year':
      return 'year';
    default:
      return 'day'; // Default fallback
  }
};

// Unified duration subtraction using date-fns functions
const subtractDuration = (date: Date, value: number, unit: DurationUnit): Date => {
  switch (unit) {
    case 'minute':
      return subMinutes(date, value);
    case 'hour':
      return subMinutes(date, value * 60);
    case 'day':
      return subDays(date, value);
    case 'month':
      return subMonths(date, value);
    case 'year':
      return subYears(date, value);
    default:
      return subDays(date, value);
  }
};

// Unified duration addition using date-fns functions
const addDuration = (date: Date, value: number, unit: DurationUnit): Date => {
  switch (unit) {
    case 'minute':
      return subMinutes(date, -value);
    case 'hour':
      return subMinutes(date, -value * 60);
    case 'day':
      return addDays(date, value);
    case 'month':
      return addMonths(date, value);
    case 'year':
      return addYears(date, value);
    default:
      return addDays(date, value);
  }
};

const endOfPeriod = (date: Date, unit: 'day' | 'month'): Date => {
  switch (unit) {
    case 'month': {
      const endMonth = endOfMonth(date);
      return endOfDayUTC(endMonth);
    }
    case 'day':
      return endOfDayUTC(date);
    default:
      return endOfDayUTC(date);
  }
};

const dateDifference = (date1: Date, date2: Date, unit: 'minutes' | 'seconds'): number => {
  switch (unit) {
    case 'minutes':
      return differenceInMinutes(date1, date2);
    case 'seconds':
      return differenceInSeconds(date1, date2);
    default:
      return differenceInSeconds(date1, date2);
  }
};

const formatUTC = (date: Date, formatStr?: string): string => {
  if (!formatStr) {
    return formatInTimeZone(date, 'UTC', momentCompatibleFormat);
  }
  const convertedFormat = convertMomentFormatToDateFns(formatStr);
  return formatInTimeZone(date, 'UTC', convertedFormat);
};

// Helper to format UTC date with a specific pattern
const formatUtcWithPattern = (date: Date, pattern: string): string => {
  return formatInTimeZone(date, 'UTC', pattern);
};

// Helper to check if a date string matches sentinel values
const matchesSentinelString = (dateString: string): boolean => {
  if (!dateString) return true;
  if (dateString === (new Date(FROM_START).toISOString())) return true;
  if (dateString === (new Date(UNTIL_END).toISOString())) return true;
  return (
    dateString.startsWith('Invalid')
    || dateString.startsWith('1970')
    || dateString.startsWith('5138')
  );
};

export const isDateStringNone = (dateString: string): boolean => matchesSentinelString(dateString);

const isNoneBasic = (date: DateInput): boolean => {
  if (!date) return true;
  if (typeof date === 'string' && date.length === 0) return true;
  if (date === (new Date(FROM_START).toISOString())) return true;
  if (date === (new Date(UNTIL_END).toISOString())) return true;
  return false;
};

let currentLocale: Locale = enUS;
const localeMap: Record<string, Locale> = {
  'en-us': enUS,
  'fr-fr': fr,
  'de-de': de,
  'es-es': es,
  'it-it': it,
  'ja-jp': ja,
  'ko-kr': ko,
  'zh-cn': zhCN,
  'ru-ru': ru,
  en: enUS,
  fr,
  de,
  es,
  it,
  ja,
  ko,
  zh: zhCN,
  ru,
};

export const setDateFormatLocale = (locale: string): void => {
  const normalizedLocale = locale.toLowerCase();
  if (localeMap[normalizedLocale]) {
    currentLocale = localeMap[normalizedLocale];
  }
};

export const ONE_SECOND = 1000;
export const FIVE_SECONDS = 5000;
export const TEN_SECONDS = FIVE_SECONDS * 2;

export const parseToUTC = (date: DateInput): Date => {
  if (date === null || date === undefined) {
    return new Date();
  }

  // Handle MomentLike objects
  if (typeof date === 'object' && 'toDate' in date && typeof (date as MomentLike).toDate === 'function') {
    return parseToUTC((date as MomentLike).toDate());
  }

  // Handle FieldOption objects (with value property)
  if (typeof date === 'object' && 'value' in date) {
    return parseToUTC(date.value);
  }

  if (date instanceof Date) {
    // Already a Date, ensure it's in UTC
    return date;
  }

  if (typeof date === 'string') {
    // For date-only strings like '2025-01-15', parse as UTC start of day
    if (/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return new Date(`${date}T00:00:00.000Z`);
    }

    // If no timezone indicator, assume UTC
    // Store original value to avoid parameter mutation
    let dateStr = date;
    if (!dateStr.includes('Z') && !dateStr.includes('+') && !dateStr.includes('-')) {
      // Check if it's already in ISO format without Z
      if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(dateStr)) {
        dateStr = `${dateStr}Z`;
      }
    }

    const parsed = parseISO(dateStr);
    if (isValid(parsed)) {
      // Already in UTC after parseISO
      return parsed;
    }

    throw new Error(`Invalid date string: ${date}`);
  }

  if (typeof date === 'number') {
    // Unix timestamps (seconds) vs milliseconds detection
    let dateValue = date;
    if (dateValue > 0 && dateValue < 10000000000) {
      // Treat as Unix timestamp in seconds, convert to milliseconds
      dateValue *= 1000;
    }
    return new Date(dateValue);
  }

  // This shouldn't happen with proper types, but handle it just in case
  return new Date();
};

export const toAPIFormat = (date: DateInput): string => {
  const utcDate = parseToUTC(date);
  return formatUtcWithPattern(utcDate, momentCompatibleFormat);
};

export const fromAPIFormat = (apiDate: string): Date => {
  return parseToUTC(apiDate);
};

export const toDisplayFormat = (date: DateInput, formatStr: string, userTimezone?: string): string => {
  const utcDate = parseToUTC(date);
  const tz = userTimezone || Intl.DateTimeFormat().resolvedOptions().timeZone;
  return formatInTimeZone(utcDate, tz, formatStr);
};

export const fromUserInput = (userInput: string, _userTimezone?: string): Date => {
  return parseISO(`${userInput}Z`);
};

export interface MomentLike {
  toDate: () => Date;
  format: (formatStr?: string) => string;
  unix: () => number;
  valueOf: () => number;
  diff: (otherDate: MomentLike | DateInput, unit: string) => number;
  subtract: (amount: number, unit: string) => MomentLike;
  add: (amount: number, unit: string) => MomentLike;
  endOf: (unit: string) => MomentLike;
  utc: () => { format: (formatStr?: string) => string };
  toISOString: () => string;
}

/** Facade for moment() - main date manipulation object */
export const parseDate = (date?: DateInput): MomentLike => {
  if (date === null) {
    const invalidDate = new Date('Invalid Date');
    return {
      toDate: () => invalidDate,
      format: () => 'Invalid date',
      unix: () => NaN,
      valueOf: () => NaN,
      diff: () => NaN,
      subtract: () => parseDate(invalidDate),
      add: () => parseDate(invalidDate),
      endOf: () => parseDate(invalidDate),
      utc: () => ({ format: () => 'Invalid date' }),
      toISOString: () => 'Invalid date',
    };
  }

  const parsed = parseToUTC(date === undefined ? new Date() : date);
  return {
    toDate: () => parsed,
    format: (formatStr?: string) => (!formatStr ? formatUtcWithPattern(parsed, momentCompatibleFormat) : format(parsed, convertMomentFormatToDateFns(formatStr))),
    unix: () => getUnixTime(parsed),
    valueOf: () => parsed.getTime(),
    diff: (otherDate: MomentLike | DateInput, unit: string) => dateDifference(parseToUTC(otherDate as DateInput), parsed, unit as 'minutes' | 'seconds'),
    subtract: (amount: number, unit: string) => parseDate(subtractDuration(parsed, amount, normalizeDurationUnit(unit))),
    add: (amount: number, unit: string) => parseDate(addDuration(parsed, amount, normalizeDurationUnit(unit))),
    endOf: (unit: string) => parseDate(endOfPeriod(parsed, unit as 'day' | 'month')),
    utc: () => ({ format: (formatStr?: string) => formatUTC(parsed, formatStr) }),
    toISOString: () => parsed.toISOString(),
  };
};

export const buildDate = (date: DateInput): Date => (isNoneBasic(date) ? new Date() : parseToUTC(date));

export const dayStartDateUTC = (date?: DateInput, fromStart = true): Date => {
  const utcDate = date ? parseToUTC(date) : parseToUTC(new Date());
  return fromStart ? startOfDayUTC(utcDate) : utcDate;
};

export const dayEndDateUTC = (date?: DateInput): Date => {
  const utcDate = date ? parseToUTC(date) : parseToUTC(new Date());
  return endOfDayUTC(utcDate);
};

export const nowInUTC = (): string => toAPIFormat(new Date());
export const timestamp = (date: DateInput): number => getUnixTime(parseToUTC(date));
export const jsDate = (date: DateInput): Date => parseToUTC(date);
export const formatTimeForToday = (time: string): string => `${format(new Date(), 'yyyy-MM-dd')}T${time}`;
export const dayAgoUTC = (): string => toAPIFormat(subtractDuration(parseToUTC(new Date()), 1, 'day'));
export const daysAgoUTC = (number: number, date?: DateInput, fromStart = true): string => toAPIFormat(subtractDuration(dayStartDateUTC(date, fromStart), number, 'day'));

// ========== DEPRECATED ALIASES ==========
export const formatDateToISO = (date: DateInput): string | null => (isNoneBasic(date) ? null : toAPIFormat(date));
/** @deprecated Use formatDateToISO() */ export const formatDate = formatDateToISO;
export function dayStartDate(): MomentLike;
export function dayStartDate(date: DateInput, fromStart?: boolean): Date;
export function dayStartDate(date?: DateInput, fromStart?: boolean): Date | MomentLike {
  if (date === undefined && arguments.length === 0) return parseDate(dayStartDateUTC(undefined, fromStart ?? true));
  return dayStartDateUTC(date, fromStart ?? true);
}
/** @deprecated Use dayEndDateUTC() */ export const dayEndDate = (date?: DateInput): Date => dayEndDateUTC(date);
/** @deprecated Use nowInUTC() */ export const now = nowInUTC;
/** @deprecated Use nowInUTC() */ export const nowUTC = nowInUTC;
/** @deprecated Use dayAgoUTC() */ export const dayAgo = dayAgoUTC;
/** @deprecated Use daysAgoUTC() */ export const daysAgo = daysAgoUTC;
/** @deprecated Use parseDate() */ export const momentDate = (date?: DateInput): MomentLike => (date === undefined ? parseDate(new Date()) : parseDate(date));
/** @deprecated Use parseDate() */ export const parse = parseDate;

export const lastDayOfThePreviousMonth = (): string => {
  const prevMonth = subMonths(parseToUTC(new Date()), 1);
  const lastDay = endOfMonth(prevMonth);
  const lastDayUtc = endOfDayUTC(lastDay);
  return formatUtcWithPattern(lastDayUtc, "yyyy-MM-dd'T'HH:mm:ss'Z'");
};

export const daysAfter = (number: number, date?: DateInput, noFuture = true): string => {
  const baseDate = date ? parseToUTC(date) : dayStartDateUTC();
  const newDate = addDays(baseDate, number);

  if (noFuture && getUnixTime(newDate) > getUnixTime(new Date())) {
    const endDate = dayEndDateUTC();
    return formatUtcWithPattern(endDate, "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
  }
  return toAPIFormat(newDate);
};

export const minutesBefore = (number: number, date?: DateInput): string => {
  const baseDate = date ? parseToUTC(date) : dayStartDateUTC();
  const result = subtractDuration(baseDate, number, 'minute');
  return toAPIFormat(result);
};

export const monthsAgo = (number: number): string => {
  const utcStart = dayStartDateUTC();
  const result = subtractDuration(utcStart, number, 'month');
  return toAPIFormat(result);
};

export const yearsAgo = (number: number): string => {
  const utcStart = dayStartDateUTC();
  const result = subtractDuration(utcStart, number, 'year');
  return toAPIFormat(result);
};

export const yearFormat = (data: DateInput): string => {
  if (!data || data === '-') return '';
  try {
    return format(parseToUTC(data), yearDateFormat);
  } catch {
    return '';
  }
};

export const dateFormat = (data: DateInput, specificFormat: string | null = null): string => {
  if (data === '-' || isNoneBasic(data) || !data) return '';
  try {
    const convertedFormat = convertMomentFormatToDateFns(specificFormat || defaultDateFormat);
    return format(parseToUTC(data), convertedFormat);
  } catch {
    return '';
  }
};

export const minutesBetweenDates = (startDate: DateInput, endDate: DateInput): number => Math.abs(dateDifference(parseToUTC(endDate), parseToUTC(startDate), 'minutes')) + 1;
export const secondsBetweenDates = (startDate: DateInput, endDate: DateInput): number => Math.abs(dateDifference(parseToUTC(endDate), parseToUTC(startDate), 'seconds')) + 1;

export const formatSeconds = (seconds: number): string => {
  const pad = (v: number) => (v < 10 ? `0${v}` : String(v));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  return `${h ? `${pad(h)}:` : ''}${m || h ? `${pad(m)}:` : ''}${pad(s)}`;
};

export const stringFormatMinutes = (input: number, t_i18n: TranslationFunction): string => {
  const d = Math.floor(input / 1440);
  const h = Math.floor((input % 1440) / 60);
  const m = Math.floor(input % 60);
  const parts = [
    d ? `${d} ${t_i18n('days')}` : '',
    h ? `${h} ${t_i18n('hours')}` : '',
    `${m} ${t_i18n('minutes')}`,
  ].filter(Boolean);
  return parts.join(' ');
};

export const computerRelativeDate = (relativeDate: string): string | null => {
  if (relativeDate.includes('days')) {
    const days = parseInt(relativeDate.split('-')[1], 10);
    const currentDate = parseToUTC(new Date());
    const result = subDays(currentDate, days);
    return toAPIFormat(result);
  }
  if (relativeDate.includes('months')) {
    const months = parseInt(relativeDate.split('-')[1], 10);
    return monthsAgo(months);
  }
  if (relativeDate.includes('years')) {
    const years = parseInt(relativeDate.split('-')[1], 10);
    return yearsAgo(years);
  }
  return null;
};

export const streamEventIdToDate = (streamEventId: string | null | undefined): MomentLike => {
  if (!streamEventId) return parseDate(0);
  const timestampStr = streamEventId.split('-')[0];
  const timestampValue = parseInt(timestampStr, 10);
  return parseDate(timestampValue);
};

export const formatUptime = (uptimeInSeconds: number | null | undefined, t_i18n: TranslationFunction): string => {
  if (uptimeInSeconds == null) return t_i18n('Not available');
  const d = Math.floor(uptimeInSeconds / 86400);
  const h = Math.floor((uptimeInSeconds % 86400) / 3600);
  const m = Math.floor((uptimeInSeconds % 3600) / 60);
  const s = uptimeInSeconds % 60;
  const parts = [
    d > 0 ? `${d} ${t_i18n(d === 1 ? 'day' : 'days')}` : '',
    h > 0 ? `${h} ${t_i18n(h === 1 ? 'hour' : 'hours')}` : '',
    m > 0 ? `${m} ${t_i18n(m === 1 ? 'minute' : 'minutes')}` : '',
  ].filter(Boolean);
  return parts.length === 0 ? `${s} ${t_i18n(s === 1 ? 'second' : 'seconds')}` : parts.join(', ');
};

export const dateFiltersValueForDisplay = (dateFilterValue: DateInput, filterOperator?: FilterOperator): Date | string | number => {
  if (filterOperator && dateFilterValue && ['lte', 'gt'].includes(filterOperator)) {
    return subDays(parseToUTC(dateFilterValue), 1);
  }
  // Ensure we return something that Date constructor can handle
  if (dateFilterValue === null || dateFilterValue === undefined) {
    return new Date();
  }
  if (typeof dateFilterValue === 'string' || typeof dateFilterValue === 'number' || dateFilterValue instanceof Date) {
    return dateFilterValue;
  }
  // For complex objects, convert to Date
  return parseToUTC(dateFilterValue);
};

export const humanizeDateDuration = (value: number | null | undefined, unit: string): string => {
  if (value === null || value === undefined || value === 0) {
    return formatDistanceToNow(new Date(), {
      addSuffix: false,
      locale: currentLocale,
    });
  }

  const nowDate = new Date();
  const normalizedUnit = normalizeDurationUnit(unit);

  // Use unified subtractDuration with normalized unit
  const dateToCompare = subtractDuration(nowDate, normalizedUnit === 'hour' ? value * 60 : value, normalizedUnit === 'hour' ? 'minute' : normalizedUnit);

  return formatDistanceToNow(dateToCompare, {
    addSuffix: false,
    locale: currentLocale,
  });
};

export const isNone = (date: DateInput): boolean => {
  if (isNoneBasic(date)) return true;
  const parsedDate = parseDate(date).format();
  return matchesSentinelString(parsedDate);
};
