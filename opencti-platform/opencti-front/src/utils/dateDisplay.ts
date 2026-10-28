import moment from 'moment';
import type { IntlShape } from 'react-intl';
import { EMPTY_VALUE } from './String';

// How the dates of tables are displayed, set on the platform and overridden by each user.
// "auto" keeps the display of each column: the date written in the language, with or without its time.
export type DateFormat = 'auto' | 'iso';
export type TimeFormat = 'auto' | 'none' | 'minutes' | 'seconds';

export interface DateDisplay {
  dateFormat: DateFormat;
  timeFormat: TimeFormat;
}

export const DEFAULT_DATE_DISPLAY: DateDisplay = { dateFormat: 'auto', timeFormat: 'auto' };

const DATE_FORMATS: DateFormat[] = ['auto', 'iso'];
const TIME_FORMATS: TimeFormat[] = ['auto', 'none', 'minutes', 'seconds'];

// The offset tells which time zone the time is in, as it is the one of the browser.
const ISO_PATTERNS: Record<Exclude<TimeFormat, 'auto'>, string> = {
  none: 'YYYY-MM-DD',
  minutes: 'YYYY-MM-DD HH:mmZ',
  seconds: 'YYYY-MM-DD HH:mm:ssZ',
};

// Choices of the platform settings and of the user profile. "auto" keeps the default of each column for the platform, and follows the platform for a user.
const automaticLabel = (t: (key: string) => string, scope: 'platform' | 'user') => t(scope === 'user' ? 'Platform default' : 'Default');

export const dateFormatOptions = (t: (key: string) => string, scope: 'platform' | 'user'): { value: DateFormat; label: string }[] => [
  { value: 'auto', label: automaticLabel(t, scope) },
  { value: 'iso', label: t('ISO 8601 (YYYY-MM-DD)') },
];

export const timeFormatOptions = (t: (key: string) => string, scope: 'platform' | 'user'): { value: TimeFormat; label: string }[] => [
  { value: 'auto', label: automaticLabel(t, scope) },
  { value: 'none', label: t('Date only') },
  { value: 'minutes', label: t('Hours and minutes (HH:mm)') },
  { value: 'seconds', label: t('Hours, minutes and seconds (HH:mm:ss)') },
];

// A user format left to "auto" follows the platform one.
const resolveFormat = <T extends string>(allowed: T[], userFormat?: string | null, platformFormat?: string | null): T => {
  const isSet = (format?: string | null): format is T => !!format && format !== 'auto' && allowed.includes(format as T);
  if (isSet(userFormat)) return userFormat;
  if (isSet(platformFormat)) return platformFormat;
  return 'auto' as T;
};

export const resolveDateDisplay = (
  me: { date_format?: string | null; time_format?: string | null },
  settings: { platform_date_format?: string | null; platform_time_format?: string | null },
): DateDisplay => ({
  dateFormat: resolveFormat(DATE_FORMATS, me.date_format, settings.platform_date_format),
  timeFormat: resolveFormat(TIME_FORMATS, me.time_format, settings.platform_time_format),
});

/**
 * Date of a table cell. The column decides whether its time is shown by default,
 * the date display of the user can force it and write the date as ISO 8601.
 */
export const formatTableDate = (
  intl: IntlShape,
  date: string | Date,
  { dateFormat, timeFormat }: DateDisplay,
  columnTime: 'none' | 'seconds',
) => {
  if (!moment(date).isValid()) return EMPTY_VALUE;
  const time = timeFormat === 'auto' ? columnTime : timeFormat;
  if (dateFormat === 'iso') {
    return moment(date).format(ISO_PATTERNS[time]);
  }
  return intl.formatDate(date, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    ...(time !== 'none' && { hour: 'numeric', minute: 'numeric' }),
    ...(time === 'seconds' && { second: 'numeric' }),
    // A time chosen as HH:mm or HH:mm:ss is shown on 24 hours, whatever the language.
    ...(timeFormat !== 'auto' && time !== 'none' && { hourCycle: 'h23' }),
  });
};
