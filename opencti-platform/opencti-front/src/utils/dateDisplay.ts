import moment from 'moment';
import type { IntlShape } from 'react-intl';

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

const ISO_PATTERNS: Record<Exclude<TimeFormat, 'auto'>, string> = {
  none: 'YYYY-MM-DD',
  minutes: 'YYYY-MM-DD HH:mm',
  seconds: 'YYYY-MM-DD HH:mm:ss',
};

// Choices of the platform settings and of the user profile. "auto" follows the platform for a user, the language for the platform.
export const dateFormatOptions = (t: (key: string) => string): { value: DateFormat; label: string }[] => [
  { value: 'auto', label: t('Automatic') },
  { value: 'iso', label: t('ISO 8601 (YYYY-MM-DD)') },
];

export const timeFormatOptions = (t: (key: string) => string): { value: TimeFormat; label: string }[] => [
  { value: 'auto', label: t('Automatic') },
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
  });
};
