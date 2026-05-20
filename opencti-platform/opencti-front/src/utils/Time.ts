import moment, { Moment } from 'moment-timezone';
import { subDays } from 'date-fns';
import { isNone } from '../components/i18n';

const defaultDateFormat = 'YYYY-MM-DD';
const yearDateFormat = 'YYYY';

export const ONE_SECOND = 1000;
export const FIVE_SECONDS = 5000;
export const TEN_SECONDS = FIVE_SECONDS * 2;
export const THIRTY_SECONDS = TEN_SECONDS * 3;

type DateInput = string | number | Date;

export const buildDate = (date: DateInput | undefined | null): Date | null => {
  if (!date || isNone(date)) {
    return null;
  }
  return new Date(date);
};

export const parse = (date: DateInput): Moment => moment(date);

export const formatDate = (date: DateInput | null | undefined): string | null => {
  if (!date || isNone(date)) {
    return null;
  }
  return parse(date).format();
};

export const dayStartDate = (date: DateInput | null = null, fromStart = true): Date => {
  let start = new Date();
  if (date) {
    start = parse(date).toDate();
  }
  if (fromStart) {
    start.setHours(0, 0, 0, 0);
  }
  return start;
};

export const dayEndDate = (date: DateInput | null = null): Date => {
  let end = new Date();
  if (date) {
    end = parse(date).toDate();
  }
  end.setHours(23, 59, 59, 999);
  return end;
};

export const now = (): string => moment().format();

export const nowUTC = (): string => moment().utc().format();

export const dayAgo = (): string => moment().subtract(1, 'days').format();

export const daysAgo = (
  number: number | string,
  date: DateInput | null = null,
  fromStart = true,
): string =>
  moment(dayStartDate(date ?? null, fromStart)).subtract(number, 'days').format();

export const lastDayOfThePreviousMonth = (): string => moment().subtract(1, 'months').endOf('month').format();

export const daysAfter = (
  number: number | string,
  date?: DateInput | null,
  noFuture = true,
): string => {
  const newDate = moment(date || dayStartDate())
    .add(number, 'days')
    .format();
  if (noFuture && moment(newDate).unix() > moment().unix()) {
    return moment(dayEndDate()).format();
  }
  return newDate;
};

export const minutesBefore = (
  number: number | string,
  date?: DateInput | null,
): string =>
  moment(date || dayStartDate())
    .subtract(number, 'minutes')
    .format();

export const monthsAgo = (number: number | string): string => moment(dayStartDate()).subtract(number, 'months').format();

export const yearsAgo = (number: number | string): string => moment(dayStartDate()).subtract(number, 'years').format();

export const yearFormat = (data: DateInput): string => (data && data !== '-' ? parse(data).format(yearDateFormat) : '');

/**
 * Format a date using a specific format string, or the default 'YYYY-MM-DD'.
 *
 * @param data The date to format.
 * @param specificFormat Optional format string (defaults to 'YYYY-MM-DD').
 * @returns The formatted date string, or null if the date is empty.
 */
export const dateFormat = (
  data: DateInput | null,
  specificFormat: string | null = null,
): string | null => {
  if (isNone(data)) {
    return null;
  }
  return data && data !== '-'
    ? parse(data).format(specificFormat || defaultDateFormat)
    : '';
};

export const formatTimeForToday = (time: string): string => {
  const today = dateFormat(new Date(), 'YYYY-MM-DD');
  return `${today}T${time}`;
};

export const timestamp = (date: DateInput): number => parse(date).unix();

export const jsDate = (date: DateInput): Date => parse(date).toDate();

export const minutesBetweenDates = (startDate: DateInput, endDate: DateInput): number => {
  const start = parse(startDate);
  const end = parse(endDate);
  return end.diff(start, 'minutes') + 1;
};

export const secondsBetweenDates = (startDate: DateInput, endDate: DateInput): number => {
  const start = parse(startDate);
  const end = parse(endDate);
  return end.diff(start, 'seconds') + 1;
};

export const daysBetweenDates = (startDate: DateInput, endDate: DateInput): number => {
  const start = parse(startDate);
  const end = parse(endDate);
  return end.diff(start, 'days') + 1;
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
export const computerRelativeDate = (relativeDate: string): string | null => {
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

export const streamEventIdToDate = (streamEventId: string | undefined | null): Moment => {
  return parse(parseInt((streamEventId || '-').split('-')[0], 10));
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
  dateFilterValue: Date | string | null,
  filterOperator: string | null | undefined,
): Date | string | null;
export function dateFiltersValueForDisplay(
  dateFilterValue: Date | string | null,
  filterOperator: string | null | undefined,
): Date | string | null {
  if (filterOperator && dateFilterValue && ['lte', 'gt'].includes(filterOperator)) {
    return subDays(dateFilterValue, 1);
  }
  return dateFilterValue;
}
