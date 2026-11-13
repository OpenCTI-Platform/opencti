import { booleanConf, ES_TRANSLOG_REQUEST_FEATURE_FLAG, isFeatureEnabled } from '../config/conf';

const ES_SCRIPT_FILTER_ENABLED: boolean = booleanConf('elasticsearch:unsecure_script_filter_enabled', false);
export const isEsScriptFilterEnabled = () => {
  return ES_SCRIPT_FILTER_ENABLED;
};

export type TranslogDurability = 'async' | 'request';
// Translog durability of the platform indices, applied at every start to the platform templates and to
// every existing platform index (Elasticsearch only). 'async' acknowledges a write before its translog
// fsync, and is the platform default; the ES_TRANSLOG_REQUEST flag restores the Elasticsearch default
// 'request', which waits for the fsync.
export const isTranslogRequestForced = (): boolean => isFeatureEnabled(ES_TRANSLOG_REQUEST_FEATURE_FLAG);
export const getTranslogDurability = (): TranslogDurability => (isTranslogRequestForced() ? 'request' : 'async');
