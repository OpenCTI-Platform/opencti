import moment from 'moment-timezone';
import { isNone } from '../components/i18n';

const defaultDateFormat = 'YYYY-MM-DD';
const yearDateFormat = 'YYYY';

export const FIVE_SECONDS = 5000;
export const TEN_SECONDS = FIVE_SECONDS * 2;

export const buildDate = (date) => {
  if (isNone(date)) {
    return null;
  }
  return new Date(date);
};

export const parse = (date) => moment(date);

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

export const dayAgo = () => moment().subtract(1, 'days').format();

export const daysAgo = (number, date = null, fromStart = true) => moment(dayStartDate(date, fromStart)).subtract(number, 'days').format();

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

export const timestamp = (date) => parse(date).unix();

export const jsDate = (date) => parse(date).toDate();

export const minutesBetweenDates = (startDate, endDate) => {
  const start = parse(startDate);
  const end = parse(endDate);
  return end.diff(start, 'minutes') + 1;
};
