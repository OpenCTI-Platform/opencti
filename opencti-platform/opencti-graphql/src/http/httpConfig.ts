import nconf from 'nconf';
import { booleanConf, DEV_MODE } from '../config/conf';

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
