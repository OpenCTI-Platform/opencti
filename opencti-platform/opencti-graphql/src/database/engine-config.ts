import { booleanConf } from '../config/conf';

const ES_SCRIPT_FILTER_ENABLED: boolean = booleanConf('elasticsearch:unsecure_script_filter_enabled', false);
export const isEsScriptFilterEnabled = () => {
  return ES_SCRIPT_FILTER_ENABLED;
};
