import { stringArrayConf } from './conf-utils';

const APP_URI_DENY_LIST = stringArrayConf('app:uri_deny_list');

export const uriDenyList = () => APP_URI_DENY_LIST;
