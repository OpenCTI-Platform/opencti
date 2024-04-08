import Moment from 'moment';
import { extendMoment } from 'moment-range';
import * as R from 'ramda';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_BANK_ACCOUNT,
  ENTITY_DIRECTORY,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_MEDIA_CONTENT,
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PAYMENT_CARD,
  ENTITY_PERSONA,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE
} from '../schema/stixCyberObservable';

const DEFAULT_TRUNCATE_LIMIT = 64;

//----------------------------------------------------------------------------------------------------------------------
// Date formatting

const moment = extendMoment(Moment);

export const FROM_START = 0;
export const FROM_START_STR = '1970-01-01T00:00:00.000Z';
export const UNTIL_END = 100000000000000;
export const UNTIL_END_STR = '5138-11-16T09:46:40.000Z';

const dateFormat = 'YYYY-MM-DDTHH:mm:ss.SSS';

export const utcDate = (date) => (date ? moment(date).utc() : moment().utc());
export const now = () => utcDate().toISOString();
export const nowTime = () => timeFormat(now());
export const sinceNowInMinutes = (lastModified) => {
  const diff = utcDate().diff(utcDate(lastModified));
  const duration = moment.duration(diff);
  return Math.floor(duration.asMinutes());
};
export const sinceNowInDays = (lastModified) => {
  return sinceNowInMinutes(lastModified) / 1440;
};
export const prepareDate = (date) => utcDate(date).format(dateFormat);
export const yearFormat = (date) => utcDate(date).format('YYYY');
export const monthFormat = (date) => utcDate(date).format('YYYY-MM');
export const dayFormat = (date) => utcDate(date).format('YYYY-MM-DD');
export const timeFormat = (date) => utcDate(date).format('YYYY-MM-DD HH:mm');

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

/**
 * @param {number} days Number of days
 * @return {string} ISO Date string
 */
export const daysAgo = (days) => {
  const currentDate = new Date();
  currentDate.setDate(currentDate.getDate() - days);
  return currentDate.toISOString().split('T')[0];
};

const hashes = ['SHA-512', 'SHA-256', 'SHA-1', 'MD5'];
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

// Moment.js parsing is only compatible with ISO-8601 and RFC-2822 date formats
// see https://momentjs.com/docs/#/parsing/string/
// We handle cases that might happen in the platform (data ingestion for instance)
export const sanitizeForMomentParsing = (date) => date
  .replace('CET', '+0100') // reported in RSS feeds
  .replace('CEST', '+0200'); // reported in RSS feeds
  // add more if needed.

//----------------------------------------------------------------------------------------------------------------------

export const truncate = (str, limit = DEFAULT_TRUNCATE_LIMIT, withPoints = true) => {
  if (str === undefined || str === null || str.length <= limit) {
    return str;
  }
  const trimmedStr = str.substr(0, limit);
  if (!withPoints) {
    return trimmedStr;
  }
  if (!trimmedStr.includes(' ')) {
    return `${trimmedStr}...`;
  }
  return `${trimmedStr.substr(0, Math.min(trimmedStr.length, trimmedStr.lastIndexOf(' ')))}...`;
};

const formatSoftware = (stixCyberObservable) => {
  const value = stixCyberObservable.name || stixCyberObservable.cpe || stixCyberObservable.swid || 'Unknown';
  if (value !== 'Unknown' && !!stixCyberObservable.version) {
    return `${value} (${stixCyberObservable.version})`;
  }
  return value;
};

// TODO for now this list is duplicated in Front, think about updating it aswell
export const observableValue = (stixCyberObservable) => {
  switch (stixCyberObservable.entity_type) {
    case ENTITY_AUTONOMOUS_SYSTEM:
      return stixCyberObservable.name || stixCyberObservable.number || 'Unknown';
    case ENTITY_DIRECTORY:
      return stixCyberObservable.path || 'Unknown';
    case ENTITY_EMAIL_MESSAGE:
      return stixCyberObservable.body || stixCyberObservable.subject;
    case ENTITY_HASHED_OBSERVABLE_ARTIFACT:
      return hashValue(stixCyberObservable) || stixCyberObservable.payload_bin || stixCyberObservable.url || 'Unknown';
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
      return formatSoftware(stixCyberObservable);
    case ENTITY_USER_ACCOUNT:
      return stixCyberObservable.account_login || stixCyberObservable.user_id || 'Unknown';
    case ENTITY_BANK_ACCOUNT:
      return stixCyberObservable.iban || stixCyberObservable.number || 'Unknown';
    case ENTITY_PAYMENT_CARD:
      return stixCyberObservable.card_number || stixCyberObservable.holder_name || 'Unknown';
    case ENTITY_WINDOWS_REGISTRY_KEY:
      return stixCyberObservable.attribute_key || 'Unknown';
    case ENTITY_WINDOWS_REGISTRY_VALUE_TYPE:
      return stixCyberObservable.name || stixCyberObservable.data || 'Unknown';
    case ENTITY_MEDIA_CONTENT:
      return stixCyberObservable.content || stixCyberObservable.title || stixCyberObservable.url || 'Unknown';
    case ENTITY_PERSONA:
      return stixCyberObservable.persona_name || 'Unknown';
    default:
      return stixCyberObservable.value || stixCyberObservable.name || 'Unknown';
  }
};

// Be careful to align this script with the previous function
export const runtimeFieldObservableValueScript = () => {
  return `
    def getFieldValue(def doc, def key) {
      if (!doc.containsKey(key)) {
        return 'Unknown';
      }
      if (doc.containsKey(key + '.keyword')) {
        if (doc[key + '.keyword'].size()!=0) {
          return doc[key + '.keyword'].value;
        }
      } else if (doc[key].size()!=0) {
        return String.valueOf(doc[key].value);
      }
      return 'Unknown';
    }
    def getFieldsValue(def doc, def fields) {
      def value = 'Unknown';
      for (def field : fields) {
        value = getFieldValue(doc, field);
        if (value != 'Unknown') {
          return value;
        }
      }
      return value;
    }
    def type = doc['entity_type.keyword'].value;
    if (type == 'autonomous-system') {
      emit(getFieldsValue(doc, ['name', 'number']))
    } else if (type == 'directory') {
      emit(getFieldValue(doc, 'path'))
    } else if (type == 'email-message') {
      emit(getFieldsValue(doc, ['body', 'subject']))
    } else if (type == 'artifact') {
      emit(getFieldsValue(doc, ['hashes.SHA-256','hashes.SHA-512', 'hashes.SHA-1', 'hashes.MD5', 'payload_bin']))
    } else if (type == 'stixfile') {
      emit(getFieldsValue(doc, ['hashes.SHA-256','hashes.SHA-512', 'hashes.SHA-1', 'hashes.MD5', 'name']))
    } else if (type == 'x509-certificate') {
      emit(getFieldsValue(doc, ['hashes.SHA-256','hashes.SHA-512', 'hashes.SHA-1', 'hashes.MD5', 'subject', 'issuer']))
    } else if (type == 'mutex') {
      emit(getFieldValue(doc, 'name'))
    } else if (type == 'network-traffic') {
      emit(getFieldValue(doc, 'dst_port'))
    } else if (type == 'process') {
      emit(getFieldsValue(doc, ['pid', 'command_line']))
    } else if (type == 'software') {
      emit(getFieldValue(doc, 'name'))
    } else if (type == 'user-account') {
      emit(getFieldsValue(doc, ['account_login', 'user_id']))
    } else if (type == 'bank-account') {
      emit(getFieldValue(doc, 'iban'))
    } else if (type == 'payment-card') {
      emit(getFieldValue(doc, 'card_number'))
    } else if (type == 'media-content') {
      emit(getFieldsValue(doc, ['content', 'title', 'url']))
    } else if (type == 'windows-registry-key') {
      emit(getFieldValue(doc, 'attribute_key'))
    } else if (type == 'windows-registry-value-type') {
      emit(getFieldsValue(doc, ['name', 'data']))
    } else {
      emit(getFieldValue(doc, 'value'))
    }
  `;
};

//----------------------------------------------------------------------------------------------------------------------

export const mergeDeepRightAll = R.unapply(R.reduce(R.mergeDeepRight, {}));
