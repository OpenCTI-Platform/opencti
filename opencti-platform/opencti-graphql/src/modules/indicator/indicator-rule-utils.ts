import type { IndicatorRuleLogsource } from './indicator-types';

interface IndicatorRuleMetadataInput {
  x_opencti_rule_status?: string | null;
  x_opencti_rule_level?: string | null;
  x_opencti_rule_logsource?: { category?: string | null; product?: string | null; service?: string | null } | null;
}

interface IndicatorRuleMetadata {
  x_opencti_rule_status?: string;
  x_opencti_rule_level?: string;
  x_opencti_rule_logsource?: IndicatorRuleLogsource;
}

const normalizeRuleValue = (value: string | null | undefined): string | undefined => {
  if (value === null || value === undefined) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  return normalized.length > 0 ? normalized : undefined;
};

/**
 * Normalize the detection rule metadata of an indicator (Sigma status, level and logsource).
 * Values are trimmed and lower-cased so that rules coming from different sources (Sigma, SIEM, EDR)
 * can be filtered and mapped consistently. Empty values are dropped.
 */
export const normalizeIndicatorRuleLogsource = (logsource: IndicatorRuleMetadataInput['x_opencti_rule_logsource']): IndicatorRuleLogsource | undefined => {
  if (!logsource) {
    return undefined;
  }
  const category = normalizeRuleValue(logsource.category);
  const product = normalizeRuleValue(logsource.product);
  const service = normalizeRuleValue(logsource.service);
  if (!category && !product && !service) {
    return undefined;
  }
  return {
    ...(category ? { category } : {}),
    ...(product ? { product } : {}),
    ...(service ? { service } : {}),
  };
};

type RuleMetadataKeys = 'x_opencti_rule_status' | 'x_opencti_rule_level' | 'x_opencti_rule_logsource';

export const withoutIndicatorRuleMetadata = <T extends IndicatorRuleMetadataInput>(input: T): Omit<T, RuleMetadataKeys> => {
  const { x_opencti_rule_status: _status, x_opencti_rule_level: _level, x_opencti_rule_logsource: _logsource, ...rest } = input;
  return rest;
};

export const normalizeIndicatorRuleMetadata = (input: IndicatorRuleMetadataInput): IndicatorRuleMetadata => {
  const metadata: IndicatorRuleMetadata = {};
  const status = normalizeRuleValue(input.x_opencti_rule_status);
  if (status) metadata.x_opencti_rule_status = status;
  const level = normalizeRuleValue(input.x_opencti_rule_level);
  if (level) metadata.x_opencti_rule_level = level;
  const logsource = normalizeIndicatorRuleLogsource(input.x_opencti_rule_logsource);
  if (logsource) metadata.x_opencti_rule_logsource = logsource;
  return metadata;
};
