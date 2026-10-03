import { describe, expect, it } from 'vitest';
import {
  normalizeIndicatorRuleEditInputs,
  normalizeIndicatorRuleLogsource,
  normalizeIndicatorRuleMetadata,
  withoutIndicatorRuleMetadata,
} from '../../../../src/modules/indicator/indicator-rule-utils';

describe('Indicator detection rule metadata', () => {
  it('should lower-case and trim the rule status and level', () => {
    expect(normalizeIndicatorRuleMetadata({ x_opencti_rule_status: ' Stable ', x_opencti_rule_level: 'HIGH' })).toEqual({
      x_opencti_rule_status: 'stable',
      x_opencti_rule_level: 'high',
    });
  });
  it('should drop empty values', () => {
    expect(normalizeIndicatorRuleMetadata({ x_opencti_rule_status: '  ', x_opencti_rule_level: null, x_opencti_rule_logsource: { category: '' } })).toEqual({});
  });
  it('should keep only the set log source fields', () => {
    expect(normalizeIndicatorRuleLogsource({ category: 'Process_Creation', product: 'Windows', service: null })).toEqual({
      category: 'process_creation',
      product: 'windows',
    });
    expect(normalizeIndicatorRuleLogsource(null)).toBeUndefined();
  });
  it('should remove the raw metadata from an input', () => {
    expect(withoutIndicatorRuleMetadata({ name: 'rule', x_opencti_rule_status: 'test', x_opencti_rule_level: 'low', x_opencti_rule_logsource: { product: 'linux' } }))
      .toEqual({ name: 'rule' });
  });
  it('should normalize the rule metadata of field patches', () => {
    expect(normalizeIndicatorRuleEditInputs([
      { key: 'x_opencti_rule_status', value: [' Stable '] },
      { key: 'x_opencti_rule_level', value: ['  '] },
      { key: 'x_opencti_rule_logsource', value: [{ category: 'Process_Creation', product: ' Windows' }] },
      { key: 'name', value: [' Kept as is '] },
    ])).toEqual([
      { key: 'x_opencti_rule_status', value: ['stable'] },
      { key: 'x_opencti_rule_level', value: [] },
      { key: 'x_opencti_rule_logsource', value: [{ category: 'process_creation', product: 'windows' }] },
      { key: 'name', value: [' Kept as is '] },
    ]);
  });
});
