import useHelper from './useHelper';

// The one place the flag string lives on the front. Backend counterpart is
// INGESTION_HEALTH_FEATURE_FLAG in config/conf.js — the string is duplicated
// rather than imported, the same way workflowFeatureFlag.ts does it, because
// the two packages share no module.
export const INGESTION_HEALTH_FEATURE_FLAG = 'INGESTION_HEALTH';

// With the flag off every health surface is hidden. The GraphQL field itself
// soft-fails to null, so a query that still selects it succeeds and simply gets
// nothing back — this hook is what stops the empty result being rendered as a
// column of "Unknown" chips.
const useIngestionHealthEnabled = (): boolean => {
  const { isFeatureEnable } = useHelper();
  return isFeatureEnable(INGESTION_HEALTH_FEATURE_FLAG);
};

export default useIngestionHealthEnabled;
