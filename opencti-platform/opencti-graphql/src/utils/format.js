import Moment from 'moment';
import { extendMoment } from 'moment-range';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_DIRECTORY,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE,
} from '../schema/stixCyberObservable';

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

const hashes = ['SHA-256', 'SHA-1', 'MD5'];
export const hashValue = (stixCyberObservable) => {
  if (stixCyberObservable.hashes) {
    for (let index = 0; index < hashes.length; index += 1) {
      const algo = hashes[index];
      if (stixCyberObservable.hashes[algo]) {
        return stixCyberObservable.hashes[algo];
      }
    }
  }
  return null;
};
export const observableValue = (stixCyberObservable) => {
  switch (stixCyberObservable.entity_type) {
    case ENTITY_AUTONOMOUS_SYSTEM:
      return stixCyberObservable.name || stixCyberObservable.number || 'Unknown';
    case ENTITY_DIRECTORY:
      return stixCyberObservable.path || 'Unknown';
    case ENTITY_EMAIL_MESSAGE:
      return stixCyberObservable.body || stixCyberObservable.subject;
    case ENTITY_HASHED_OBSERVABLE_ARTIFACT:
      return hashValue(stixCyberObservable) || stixCyberObservable.payload_bin || 'Unknown';
    case ENTITY_HASHED_OBSERVABLE_STIX_FILE:
      return hashValue(stixCyberObservable) || stixCyberObservable.name || 'Unknown';
    case ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE:
      return hashValue(stixCyberObservable) || stixCyberObservable.subject || stixCyberObservable.issuer || 'Unknown';
    case ENTITY_MUTEX:
      return stixCyberObservable.name || 'Unknown';
    case ENTITY_NETWORK_TRAFFIC:
      return stixCyberObservable.dst_port || 'Unknown';
    case ENTITY_PROCESS:
      return stixCyberObservable.pid || stixCyberObservable.command_line || 'Unknown';
    case ENTITY_SOFTWARE:
      return stixCyberObservable.name || 'Unknown';
    case ENTITY_USER_ACCOUNT:
      return stixCyberObservable.account_login || stixCyberObservable.user_id || 'Unknown';
    case ENTITY_WINDOWS_REGISTRY_KEY:
      return stixCyberObservable.attribute_key || 'Unknown';
    case ENTITY_WINDOWS_REGISTRY_VALUE_TYPE:
      return stixCyberObservable.name || stixCyberObservable.data || 'Unknown';
    default:
      return stixCyberObservable.value || 'Unknown';
  }
};
