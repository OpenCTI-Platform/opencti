import { booleanConf, ES_TRANSLOG_ASYNC_FEATURE_FLAG, isFeatureEnabled } from '../config/conf';

const ES_SCRIPT_FILTER_ENABLED: boolean = booleanConf('elasticsearch:unsecure_script_filter_enabled', false);
export const isEsScriptFilterEnabled = () => {
  return ES_SCRIPT_FILTER_ENABLED;
};

export type TranslogDurability = 'async' | 'request';
// Translog durability of the platform indices, decided by the feature flag alone and applied at every
// start to the platform templates and to every existing platform index (Elasticsearch only). The
// platform keeps 'request', the Elasticsearch default, which fsyncs the translog before acknowledging
// a write; the ES_TRANSLOG_ASYNC flag asks for 'async', which acknowledges first.
export const isTranslogAsyncEnabled = (): boolean => isFeatureEnabled(ES_TRANSLOG_ASYNC_FEATURE_FLAG);
export const getTranslogDurability = (): TranslogDurability => (isTranslogAsyncEnabled() ? 'async' : 'request');
