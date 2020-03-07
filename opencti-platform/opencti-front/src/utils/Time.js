import moment from 'moment-timezone';

const defaultDateFormat = 'YYYY-MM-DD';
const yearDateFormat = 'YYYY';

export const FIVE_SECONDS = 5000;
export const TEN_SECONDS = FIVE_SECONDS * 2;

export const dayStartDate = () => {
  const start = new Date();
  start.setHours(0, 0, 0, 0);
  return start;
};

export const parse = (date) => moment(date);

export const now = () => moment().format();

export const dayAgo = () => moment().subtract(1, 'days').format();

export const monthsAgo = (number) => moment().subtract(number, 'months').format();

export const yearsAgo = (number) => moment().subtract(number, 'years').format();

export const yearFormat = (data) => (data && data !== '-' ? parse(data).format(yearDateFormat) : '');

export const dateFormat = (data, specificFormat) => (data && data !== '-'
  ? parse(data).format(specificFormat || defaultDateFormat)
  : '');
