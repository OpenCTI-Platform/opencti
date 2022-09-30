import Moment from 'moment';
import { extendMoment } from 'moment-range';
import * as R from 'ramda';
import {
  ENTITY_AUTONOMOUS_SYSTEM, ENTITY_BANK_ACCOUNT,
  ENTITY_DIRECTORY,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE, ENTITY_MEDIA_CONTENT,
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PAYMENT_CARD,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE
} from '../schema/stixCyberObservable';

const moment = extendMoment(Moment);

export const FROM_START = 0;
export const FROM_START_STR = '1970-01-01T00:00:00.000Z';
export const UNTIL_END = 100000000000000;
export const UNTIL_END_STR = '5138-11-16T09:46:40.000Z';

const dateFormat = 'YYYY-MM-DDTHH:mm:ss.SSS';
export const utcDate = (date) => (date ? moment(date).utc() : moment().utc());
export const now = () => utcDate().toISOString();
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
      return stixCyberObservable.name || 'Unknown';
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
      return stixCyberObservable.url || stixCyberObservable.title || 'Unknown';
    default:
      return stixCyberObservable.value || stixCyberObservable.name || 'Unknown';
  }
};

// Be careful to align this script with the previous function
export const runtimeFieldObservableValueScript = () => {
  return `
    boolean have(def doc, def key) {
      doc.containsKey(key) && doc[key + '.keyword'].size()!=0
    }
    def type = doc['entity_type.keyword'].value;
    if (type == 'autonomous-system') {
      if (have(doc, 'name')) {
        emit(doc['name.keyword'].value)
      } else if (have(doc, 'number.keyword')) {
        emit(doc['number.keyword'].value)
      } else {
        emit('Unknown')
      }
    } else if (type == 'directory') {
      if (have(doc, 'path')) {
        emit(doc['path.keyword'].value)
      } else {
        emit('Unknown')
      }
    } else if (type == 'email-message') {
      if (have(doc, 'body')) {
        emit(doc['body.keyword'].value)
      } else if (have(doc, 'subject')) {
        emit(doc['subject.keyword'].value)
      } else {
        emit('Unknown')
      }
    } else if (type == 'artifact') {
       if (have(doc, 'hashes.SHA-512')) {
         emit(doc['hashes.SHA-512.keyword'].value)
       } else if (have(doc, 'hashes.SHA-256')) {
         emit(doc['hashes.SHA-256.keyword'].value)
       } else if (have(doc, 'hashes.SHA-1')) {
         emit(doc['hashes.SHA-1.keyword'].value)
       } else if (have(doc, 'hashes.MD5')) {
         emit(doc['hashes.MD5.keyword'].value)
       } else if (have(doc, 'payload_bin')) {
         emit(doc['payload_bin.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (type == 'stixfile') {
       if (have(doc, 'hashes.SHA-256')) {
         emit(doc['hashes.SHA-256.keyword'].value)
       } else if (have(doc, 'hashes.SHA-1')) {
         emit(doc['hashes.SHA-1.keyword'].value)
       } else if (have(doc, 'hashes.MD5')) {
         emit(doc['hashes.MD5.keyword'].value)
       } else if (have(doc, 'name')) {
        emit(doc['name.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (type == 'x509-certificate') {
       if (have(doc, 'hashes.SHA-256')) {
         emit(doc['hashes.SHA-256.keyword'].value)
       } else if (have(doc, 'hashes.SHA-1')) {
         emit(doc['hashes.SHA-1.keyword'].value)
       } else if (have(doc, 'hashes.MD5')) {
         emit(doc['hashes.MD5.keyword'].value)
       } else if (have(doc, 'subject')) {
         emit(doc['subject.keyword'].value)
       } else if (have(doc, 'issuer')) {
         emit(doc['issuer.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (type == 'mutex') {
       if (have(doc, 'name')) {
         emit(doc['name.keyword'].value)
       } else {
         emit('Unknown')
       }
     } else if (type == 'network-traffic') {
       if (have(doc, 'dst_port')) {
         emit(doc['dst_port.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (type == 'process') {
       if (have(doc, 'pid')) {
         emit(doc['pid.keyword'].value)
       } else if (have(doc, 'command_line')) {
         emit(doc['command_line.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (type == 'software') {
       if (have(doc, 'name')) {
         emit(doc['name.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (type == 'user-account') {
       if (have(doc, 'account_login')) {
         emit(doc['account_login.keyword'].value)
       } else if (have(doc, 'user_id')) {
         emit(doc['user_id.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (type == 'bank-account') {
       if (have(doc, 'iban')) {
         emit(doc['iban.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (type == 'payment-card') {
       if (have(doc, 'card_number')) {
         emit(doc['card_number.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (type == 'media-content') {
       if (have(doc, 'url')) {
         emit(doc['url.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (type == 'windows-registry-key') {
       if (have(doc, 'attribute_key')) {
         emit(doc['attribute_key.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (type == 'windows-registry-value-type') {
       if (have(doc, 'name')) {
         emit(doc['name.keyword'].value)
       } else if (have(doc, 'data')) {
         emit(doc['data.keyword'].value)
       } else {
         emit('Unknown')
       }
    } else if (have(doc, 'value')) {
       emit(doc['value.keyword'].value)
    } else {
      emit('Unknown')
    }
  `;
};

export const mergeDeepRightAll = R.unapply(R.reduce(R.mergeDeepRight, {}));
