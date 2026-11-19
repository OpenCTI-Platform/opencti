import conf, { booleanConf } from '../config/conf';

const ES_SCRIPT_FILTER_ENABLED: boolean = booleanConf('elasticsearch:unsecure_script_filter_enabled', false);
export const isEsScriptFilterEnabled = () => {
  return ES_SCRIPT_FILTER_ENABLED;
};

// Pagination limits live here (not in engine.ts) so engine-query-builder can read them at module load without importing engine.
export const ES_DEFAULT_PAGINATION: number = conf.get('elasticsearch:default_pagination_result') || 500;
export const ES_MAX_PAGINATION: number = conf.get('elasticsearch:max_pagination_result') || 5000;
export const MAX_RUNTIME_RESOLUTION_SIZE: number = conf.get('elasticsearch:max_runtime_resolutions') || 5000;
