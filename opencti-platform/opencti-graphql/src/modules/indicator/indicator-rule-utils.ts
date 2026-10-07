import { FunctionalError } from '../../config/errors';
import type { IndicatorRuleLogsource } from './indicator-types';

// Same bound as the log source values of the telemetry mappings
const MAX_LOGSOURCE_VALUE_LENGTH = 256;
// Same bound as the rule status and level of the indicator creation input
const MAX_RULE_RANK_VALUE_LENGTH = 64;

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

const normalizeRuleRankValue = (value: string | null | undefined): string | undefined => {
  // A field patch does not go through the constraints of the GraphQL input
  if ((value?.trim().length ?? 0) > MAX_RULE_RANK_VALUE_LENGTH) {
    throw FunctionalError(`A rule status or level cannot be longer than ${MAX_RULE_RANK_VALUE_LENGTH} characters`, { length: value?.trim().length });
  }
  return normalizeRuleValue(value);
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
  // A field patch does not go through the constraints of the GraphQL input
  const tooLong = [logsource.category, logsource.product, logsource.service].find((value) => (value?.trim().length ?? 0) > MAX_LOGSOURCE_VALUE_LENGTH);
  if (tooLong) {
    throw FunctionalError(`A rule log source value cannot be longer than ${MAX_LOGSOURCE_VALUE_LENGTH} characters`, { length: tooLong.trim().length });
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
  const status = normalizeRuleRankValue(input.x_opencti_rule_status);
  if (status) metadata.x_opencti_rule_status = status;
  const level = normalizeRuleRankValue(input.x_opencti_rule_level);
  if (level) metadata.x_opencti_rule_level = level;
  const logsource = normalizeIndicatorRuleLogsource(input.x_opencti_rule_logsource);
  if (logsource) metadata.x_opencti_rule_logsource = logsource;
  return metadata;
};

/**
 * Same normalization for field patches, so an edited rule keeps matching the telemetry mappings
 * and the status / level rankings. A value normalized to nothing clears the field.
 */
export const normalizeIndicatorRuleEditInputs = <T extends { key: string; value: unknown[] }>(inputs: T[]): T[] => {
  return inputs.map((input) => {
    if (input.key === 'x_opencti_rule_status' || input.key === 'x_opencti_rule_level') {
      const value = input.value
        .map((v) => (typeof v === 'string' ? normalizeRuleRankValue(v) : v))
        .filter((v) => v !== undefined && v !== null);
      return { ...input, value };
    }
    if (input.key === 'x_opencti_rule_logsource') {
      const value = input.value
        .map((v) => (v && typeof v === 'object' ? normalizeIndicatorRuleLogsource(v as IndicatorRuleMetadataInput['x_opencti_rule_logsource']) : v))
        .filter((v) => v !== undefined && v !== null);
      return { ...input, value };
    }
    return input;
  });
};
