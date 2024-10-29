import moment from 'moment-timezone';
import { isNone } from '../components/i18n';

const defaultDateFormat = 'YYYY-MM-DD';
const yearDateFormat = 'YYYY';

export const ONE_SECOND = 1000;
export const FIVE_SECONDS = 5000;
export const TEN_SECONDS = FIVE_SECONDS * 2;

export const buildDate = (date) => {
  if (isNone(date)) {
    return null;
  }
  return new Date(date);
};

export const parse = (date) => moment(date);
export const formatDate = (date) => {
  if (isNone(date)) {
    return null;
  }
  return parse(date).format();
};

export const dayStartDate = (date = null, fromStart = true) => {
  let start = new Date();
  if (date) {
    start = parse(date).toDate();
  }
  if (fromStart) {
    start.setHours(0, 0, 0, 0);
  }
  return start;
};

export const dayEndDate = (date = null) => {
  let end = new Date();
  if (date) {
    end = parse(date).toDate();
  }
  end.setHours(23, 59, 59, 999);
  return end;
};

export const now = () => moment().format();

export const nowUTC = () => moment().utc().format();

export const dayAgo = () => moment().subtract(1, 'days').format();

export const daysAgo = (number, date = null, fromStart = true) => moment(dayStartDate(date, fromStart)).subtract(number, 'days').format();

export const lastDayOfThePreviousMonth = () => moment().subtract(1, 'months').endOf('month').format();

export const daysAfter = (number, date = null, noFuture = true) => {
  const newDate = moment(date || dayStartDate())
    .add(number, 'days')
    .format();
  if (noFuture && moment(newDate).unix() > moment().unix()) {
    return moment(dayEndDate()).format();
  }
  return newDate;
};

export const minutesBefore = (number, date = null) => moment(date || dayStartDate())
  .subtract(number, 'minutes')
  .format();

export const monthsAgo = (number) => moment(dayStartDate()).subtract(number, 'months').format();

export const yearsAgo = (number) => moment(dayStartDate()).subtract(number, 'years').format();

export const yearFormat = (data) => (data && data !== '-' ? parse(data).format(yearDateFormat) : '');

export const dateFormat = (data, specificFormat = null) => {
  if (isNone(data)) {
    return null;
  }
  return data && data !== '-'
    ? parse(data).format(specificFormat || defaultDateFormat)
    : '';
};

export const formatTimeForToday = (time) => {
  const today = dateFormat(new Date(), 'YYYY-MM-DD');
  return `${today}T${time}`;
};

export const timestamp = (date) => parse(date).unix();

export const jsDate = (date) => parse(date).toDate();

export const minutesBetweenDates = (startDate, endDate) => {
  const start = parse(startDate);
  const end = parse(endDate);
  return end.diff(start, 'minutes') + 1;
};

export const secondsBetweenDates = (startDate, endDate) => {
  const start = parse(startDate);
  const end = parse(endDate);
  return end.diff(start, 'seconds') + 1;
};

/**
 * Returns a string of the format "hh:MM:ss" from a given number of seconds.
 *
 * @param {number} seconds
 */
export const formatSeconds = (seconds) => {
  const ONE_MINUTE = 60;
  const ONE_HOUR = ONE_MINUTE * ONE_MINUTE;
  const leadingZero = (value) => {
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
 * Get a past date in a string format based on a relative string
 * used to compute how much time we go before.
 *
 * @param relativeDate How much time to go before (ex: days-7).
 * @return {string|null} The past date.
 */
export const computerRelativeDate = (relativeDate) => {
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
