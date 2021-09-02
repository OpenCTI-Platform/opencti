import Moment from 'moment';
import { extendMoment } from 'moment-range';

const moment = extendMoment(Moment);

export const FROM_START = 0;
export const FROM_START_STR = '1970-01-01T00:00:00.000Z';
export const UNTIL_END = 100000000000000;
export const UNTIL_END_STR = '5138-11-16T09:46:40.000Z';

const dateFormat = 'YYYY-MM-DDTHH:mm:ss.SSS';
export const utcDate = (date = undefined) => (date ? moment(date).utc() : moment().utc());
export const now = () => utcDate().toISOString();
export const sinceNowInMinutes = (lastModified) => {
  const diff = utcDate().diff(utcDate(lastModified));
  const duration = moment.duration(diff);
  return Math.floor(duration.asMinutes());
};
export const prepareDate = (date) => utcDate(date).format(dateFormat);
export const yearFormat = (date) => utcDate(date).format('YYYY');
export const monthFormat = (date) => utcDate(date).format('YYYY-MM');
export const dayFormat = (date) => utcDate(date).format('YYYY-MM-DD');
export const escape = (chars) => {
  const toEscape = chars && typeof chars === 'string';
  if (toEscape) {
    return chars.replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,');
  }
  return chars;
};
export const buildPeriodFromDates = (a, b) => moment.range(a, b);
export const computeRangeIntersection = (a, b) => {
  const range = a.intersect(b);
  if (range) {
    return { start: range.start.toISOString(), end: range.end.toISOString() };
  }
  // No range intersection, get min/max to build the range
  const minStart = moment.min([a.start, b.start]);
  const maxStop = moment.max([b.end, b.end]);
  return { start: minStart.toISOString(), end: maxStop.toISOString() };
};
export const minutesAgo = (minutes) => moment().utc().subtract(minutes, 'minutes');
export const hoursAgo = (hours) => moment().utc().subtract(hours, 'hours');
