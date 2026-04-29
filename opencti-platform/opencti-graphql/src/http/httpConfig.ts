import nconf from 'nconf';
import { stringArrayConf } from '../config/conf-utils';

const RATE_PROTECTION_IP_SKIP_LIST: string[] = stringArrayConf('app:rate_protection:ip_skip_list');
export const getRateProtectionIpSkipList = () => {
  return RATE_PROTECTION_IP_SKIP_LIST;
};

const RATE_PROTECTION_TIME_WINDOW: number = nconf.get('app:rate_protection:time_window') ?? 1;
export const getRateProtectionTimeWindowMs = () => {
  return RATE_PROTECTION_TIME_WINDOW < 1 ? 1000 : RATE_PROTECTION_TIME_WINDOW * 1000;
};

const RATE_PROTECTION_MAX_REQUESTS: number = nconf.get('app:rate_protection:max_requests') ?? 10000;
export const getRateProtectionMaxRequests = () => {
  return RATE_PROTECTION_MAX_REQUESTS;
};
