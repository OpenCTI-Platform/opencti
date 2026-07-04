import {
  format as fnsFormat,
  parseISO,
  subDays,
  subMinutes,
  subMonths,
  subYears,
  addDays,
  differenceInMinutes,
  differenceInSeconds,
  differenceInDays,
  endOfDay,
  isValid as fnsIsValid,
  isBefore,
} from 'date-fns';
import { isNone } from '../components/i18n';

const defaultDateFormat = 'yyyy-MM-dd';
const yearDateFormat = 'yyyy';

export const ONE_SECOND = 1000;
export const FIVE_SECONDS = 5000;
export const TEN_SECONDS = FIVE_SECONDS * 2;
export const THIRTY_SECONDS = TEN_SECONDS * 3;

type DateInput = string | number | Date;

const toDate = (date: DateInput): Date => {
  if (date instanceof Date) return date;
  if (typeof date === 'number') return new Date(date);
  return parseISO(date);
};

export const buildDate = (date: DateInput | undefined | null): Date | null => {
  if (!date || isNone(date)) {
    return null;
  }
  return new Date(date as string | number);
};

export const parse = (date: DateInput): Date => toDate(date);

export const formatDate = (date: DateInput | null | undefined): string | null => {
  if (!date || isNone(date)) {
    return null;
  }
  return toDate(date).toISOString();
};

export const dayStartDate = (date: DateInput | null = null, fromStart = true): Date => {
  let start = new Date();
  if (date) {
    start = toDate(date);
  }
  if (fromStart) {
    start.setHours(0, 0, 0, 0);
  }
  return start;
};

export const dayEndDate = (date: DateInput | null = null): Date => {
  let end = new Date();
  if (date) {
    end = toDate(date);
  }
  end.setHours(23, 59, 59, 999);
  return end;
};

export const now = (): string => new Date().toISOString();

export const nowUTC = (): string => new Date().toISOString();

export const dayAgo = (): string => subDays(new Date(), 1).toISOString();

export const daysAgo = (
  number: number | string,
  date: DateInput | null = null,
  fromStart = true,
): string =>
  subDays(dayStartDate(date ?? null, fromStart), Number(number)).toISOString();

export const lastDayOfThePreviousMonth = (): string => {
  const d = new Date();
  d.setDate(0); // last day of previous month
  d.setHours(23, 59, 59, 999);
  return d.toISOString();
};

export const daysAfter = (
  number: number | string,
  date?: DateInput | null,
  noFuture = true,
): string => {
  const newDate = addDays(date ? toDate(date) : dayStartDate(), Number(number));
  if (noFuture && newDate.getTime() > Date.now()) {
    return dayEndDate().toISOString();
  }
  return newDate.toISOString();
};

export const minutesBefore = (
  number: number | string,
  date?: DateInput | null,
): string =>
  subMinutes(date ? toDate(date) : dayStartDate(), Number(number)).toISOString();

export const monthsAgo = (number: number | string): string => subMonths(dayStartDate(), Number(number)).toISOString();

export const yearsAgo = (number: number | string): string => subYears(dayStartDate(), Number(number)).toISOString();

export const yearFormat = (data: DateInput): string => (data && data !== '-' ? fnsFormat(toDate(data), yearDateFormat) : '');

/**
 * Format a date using a specific format string, or the default 'YYYY-MM-DD'.
 *
 * @param data The date to format.
 * @param specificFormat Optional format string (defaults to 'yyyy-MM-dd', date-fns format).
 * @returns The formatted date string, or null if the date is empty.
 */
export const dateFormat = (
  data: DateInput | null | undefined,
  specificFormat: string | null = null,
): string | null => {
  if (isNone(data)) {
    return null;
  }
  return data && data !== '-'
    ? fnsFormat(toDate(data), specificFormat || defaultDateFormat)
    : '';
};

export const formatTimeForToday = (time: string): string => {
  const today = dateFormat(new Date(), 'yyyy-MM-dd');
  return `${today}T${time}`;
};

export function timestamp(date: DateInput): number;
export function timestamp(date: DateInput | null | undefined): number | undefined;
export function timestamp(date: DateInput | null | undefined): number | undefined {
  if (date === null || date === undefined) return undefined;
  return Math.floor(toDate(date).getTime() / 1000);
}

export const jsDate = (date: DateInput): Date => toDate(date);

export const minutesBetweenDates = (startDate: DateInput, endDate: DateInput): number => {
  return differenceInMinutes(toDate(endDate), toDate(startDate)) + 1;
};

export const secondsBetweenDates = (startDate: DateInput, endDate: DateInput): number => {
  return differenceInSeconds(toDate(endDate), toDate(startDate)) + 1;
};

export const daysBetweenDates = (startDate: DateInput, endDate: DateInput): number => {
  return differenceInDays(toDate(endDate), toDate(startDate)) + 1;
};

/**
 * Returns a string of the format "hh:MM:ss" from a given number of seconds.
 *
 * @param {number} seconds
 */
export const formatSeconds = (seconds: number): string => {
  const ONE_MINUTE = 60;
  const ONE_HOUR = ONE_MINUTE * ONE_MINUTE;
  const leadingZero = (value: number): string => {
    return value < 10 ? `0${value}` : String(value);
  };
  const hours = Math.floor(seconds / ONE_HOUR);
  let secondsLeft = seconds % ONE_HOUR;
  const minutes = Math.floor(secondsLeft / ONE_MINUTE);
  secondsLeft = Math.floor(secondsLeft % ONE_MINUTE);
  const formattedHours = hours ? `${leadingZero(hours)}:` : '';
  const formattedMins = minutes || hours ? `${leadingZero(minutes)}:` : '';
  const formattedSecs = `${leadingZero(secondsLeft)}`;
  return `${formattedHours}${formattedMins}${formattedSecs}`;
};

/**
 * Returns a string of the format "1 day 3 hours 58 minutes" from a given number of minutes.
 *
 * @param input The number of minutes.
 * @param t_i18n Translation function.
 */
export const stringFormatMinutes = (
  input: number,
  t_i18n: (s: string) => string,
): string => {
  const ONE_HOUR = 60;
  const ONE_DAY = ONE_HOUR * 24;
  const days = Math.floor(input / ONE_DAY);
  let minutesLeft = input % ONE_DAY;
  const hours = Math.floor(minutesLeft / ONE_HOUR);
  minutesLeft = Math.floor(minutesLeft % ONE_HOUR);
  const formattedDays = days ? `${String(days)} ${t_i18n('days')}` : '';
  const formattedHours = hours || days ? `${String(hours)} ${t_i18n('hours')}` : '';
  const formattedMins = `${String(minutesLeft)} ${t_i18n('minutes')}`;
  return `${formattedDays} ${formattedHours} ${formattedMins}`;
};

/**
 * Get a past date in a string format based on a relative string
 * used to compute how much time we go before.
 *
 * @param relativeDate How much time to go before (ex: days-7).
 * @return {string|null} The past date.
 */
export const computeRelativeDate = (relativeDate: string): string | null => {
  if (relativeDate.includes('days')) {
    return daysAgo(relativeDate.split('-')[1], null, false);
  }
  if (relativeDate.includes('months')) {
    return monthsAgo(relativeDate.split('-')[1]);
  }
  if (relativeDate.includes('years')) {
    return yearsAgo(relativeDate.split('-')[1]);
  }
  return null;
};

/**
 * Extracts the timestamp from a Redis stream event ID and returns it as an ISO date string.
 *
 * @param streamEventId The stream event ID to parse (in the the format "timestamp-sequence" (e.g. "1718445600000-0")).
 * @returns An ISO formatted date string.
 */
export const streamEventIdToDate = (streamEventId: string | undefined | null): string => {
  return new Date(parseInt((streamEventId || '-').split('-')[0], 10)).toISOString();
};

/**
 * Returns a human-readable string format from a given number of seconds (uptime).
 * Format: "2 days, 3 hours, 15 minutes" or "45 seconds" for short durations
 *
 * @param {number | null | undefined} uptimeInSeconds - The uptime in seconds
 * @param {function} t_i18n - Translation function for internationalization
 * @returns {string} Formatted uptime string or 'Not available' if input is null/undefined
 */
export const formatUptime = (
  uptimeInSeconds: number | null | undefined,
  t_i18n: (s: string) => string,
): string => {
  if (uptimeInSeconds == null) {
    return t_i18n('Not available');
  }

  const days = Math.floor(uptimeInSeconds / 86400);
  const hours = Math.floor((uptimeInSeconds % 86400) / 3600);
  const minutes = Math.floor((uptimeInSeconds % 3600) / 60);
  const seconds = uptimeInSeconds % 60;

  const parts: string[] = [];
  if (days > 0) parts.push(`${days} ${t_i18n(days === 1 ? 'day' : 'days')}`);
  if (hours > 0) parts.push(`${hours} ${t_i18n(hours === 1 ? 'hour' : 'hours')}`);
  if (minutes > 0) parts.push(`${minutes} ${t_i18n(minutes === 1 ? 'minute' : 'minutes')}`);

  // If uptime is less than a minute, show seconds
  if (parts.length === 0) {
    parts.push(`${seconds} ${t_i18n(seconds === 1 ? 'second' : 'seconds')}`);
  }

  return parts.join(', ');
};

/**
 * Convert a date value stored in filters to a date value displayed in frontend according to the operator
 *
 * @returns The date value to be displayed
 * @param dateFilterValue
 * @param filterOperator
 */
export function dateFiltersValueForDisplay(
  dateFilterValue: Date | string,
  filterOperator: string | null | undefined,
): Date | string;
export function dateFiltersValueForDisplay(
  dateFilterValue: Date | string | null | undefined,
  filterOperator: string | null | undefined,
): Date | string | null;
export function dateFiltersValueForDisplay(
  dateFilterValue: Date | string | null | undefined,
  filterOperator: string | null | undefined,
): Date | string | null | undefined {
  if (filterOperator && dateFilterValue && ['lte', 'gt'].includes(filterOperator)) {
    return subDays(dateFilterValue, 1);
  }
  return dateFilterValue;
}
