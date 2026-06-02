import { stringArrayConf } from '../../config/conf-utils';

const INGESTION_MANAGER_URI_DENY_LIST = stringArrayConf('ingestion_manager:uri_deny_list');
export const ingestionUriDenyList = () => {
  return INGESTION_MANAGER_URI_DENY_LIST;
};
import conf from '../../config/conf';
import { stringArrayConf } from '../../config/conf-utils';

export const INGESTION_MANAGER_SCHEDULE_TIME = conf.get('ingestion_manager:interval') || 30000;
const INGESTION_MANAGER_URI_DENY_LIST = stringArrayConf('ingestion_manager:uri_deny_list');
export const ingestionUriDenyList = () => {
  return INGESTION_MANAGER_URI_DENY_LIST;
};
