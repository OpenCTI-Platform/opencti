import nconf from 'nconf';
import { booleanConf, DEV_MODE } from '../config/conf';
import { stringArrayConf } from '../config/conf-utils';

const PUBLIC_AUTH_DOMAINS: string = nconf.get('app:public_dashboard_authorized_domains') ?? '';
export const getPublicAuthorizedDomainsFromConfiguration = () => {
  return PUBLIC_AUTH_DOMAINS.trim();
};

const IS_HTTP_ALLOWED: boolean = booleanConf('app:allow_unsecure_http_resources', true);
export const isUnsecureHttpResourceAllowed = () => {
  return IS_HTTP_ALLOWED;
};

export const isDevMode = () => {
  return DEV_MODE;
};

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
