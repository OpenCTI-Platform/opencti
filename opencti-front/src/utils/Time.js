import moment from 'moment-timezone';
import countdown from 'countdown';

const dayDateFormat = 'MMMM Do YYYY';
const timeDateFormat = 'HH:mm:ss';
const defaultDateFormat = 'YYYY-MM-DD';
const yearDateFormat = 'YYYY';

export const ONE_MINUTE = 60 * 1000;
export const FIVE_SECONDS = 5000;
export const ONE_SECOND = 1000;

export const parse = date => moment(date);

export const now = () => moment();

export const dayFormat = data => (data && data !== '-' ? parse(data).format(dayDateFormat) : '');

export const yearFormat = data => (data && data !== '-' ? parse(data).format(yearDateFormat) : '');

export const currentYear = () => yearFormat(now());

export const timeDiff = (start, end) => parse(start).diff(parse(end));

export const timeFormat = data => (data && data !== '-' ? parse(data).format(timeDateFormat) : '');

export const dateFormat = (data, specificFormat) => (data && data !== '-' ? parse(data).format(specificFormat || defaultDateFormat) : '');

export const dateToISO = (date) => {
  const momentDate = parse(date, defaultDateFormat, true);
  return momentDate.isValid() ? momentDate.format() : 'invalid-date';
};

export const dateFromNow = dateString => (dateString ? countdown(parse(dateString).toDate()).toString() : '');

export const convertToCountdown = (durationInMillis) => {
  if (durationInMillis === null) return '-';
  const end = now();
  const start = moment(end).subtract(durationInMillis, 'ms');
  return countdown(start.toDate(), end.toDate()).toString();
};

export const logDate = () => now().format('HH:mm:ss.SSS');
