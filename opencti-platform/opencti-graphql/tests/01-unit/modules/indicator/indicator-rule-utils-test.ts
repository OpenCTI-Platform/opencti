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
  it('should refuse a log source value longer than 256 characters, on creation and on field patches', () => {
    expect(normalizeIndicatorRuleLogsource({ product: ` ${'w'.repeat(256)} ` })).toEqual({ product: 'w'.repeat(256) });
    expect(() => normalizeIndicatorRuleLogsource({ service: 's'.repeat(257) })).toThrow('A rule log source value cannot be longer than 256 characters');
    expect(() => normalizeIndicatorRuleEditInputs([{ key: 'x_opencti_rule_logsource', value: [{ category: 'c'.repeat(257) }] }]))
      .toThrow('A rule log source value cannot be longer than 256 characters');
  });
  it('should refuse a rule status or level longer than 64 characters, on creation and on field patches', () => {
    expect(normalizeIndicatorRuleMetadata({ x_opencti_rule_status: ` ${'S'.repeat(64)} ` })).toEqual({ x_opencti_rule_status: 's'.repeat(64) });
    expect(() => normalizeIndicatorRuleMetadata({ x_opencti_rule_level: 'l'.repeat(65) })).toThrow('A rule status or level cannot be longer than 64 characters');
    expect(() => normalizeIndicatorRuleEditInputs([{ key: 'x_opencti_rule_status', value: ['s'.repeat(65)] }]))
      .toThrow('A rule status or level cannot be longer than 64 characters');
    expect(() => normalizeIndicatorRuleEditInputs([{ key: 'x_opencti_rule_level', value: ['l'.repeat(65)] }]))
      .toThrow('A rule status or level cannot be longer than 64 characters');
  });
  it.each([
    ['a status that is not a text', { key: 'x_opencti_rule_status', value: [5] }, 'A rule status or level must be a text'],
    ['a level that is not a text', { key: 'x_opencti_rule_level', value: [{ level: 'high' }] }, 'A rule status or level must be a text'],
    ['a log source that is a text', { key: 'x_opencti_rule_logsource', value: ['windows'] }, 'A rule log source must be an object whose category, product and service are texts'],
    ['a log source that is an empty text', { key: 'x_opencti_rule_logsource', value: [''] }, 'A rule log source must be an object whose category, product and service are texts'],
    ['a log source that is a list', { key: 'x_opencti_rule_logsource', value: [['windows']] }, 'A rule log source must be an object whose category, product and service are texts'],
    ['a log source field that is not a text', { key: 'x_opencti_rule_logsource', value: [{ category: 5 }] }, 'A rule log source must be an object whose category, product and service are texts'],
    ['a patch of one log source field', { key: 'x_opencti_rule_logsource', object_path: '/x_opencti_rule_logsource/product', value: ['windows'] }, 'A rule log source is patched as a whole'],
  ])('should refuse a field patch with %s', (_, input, message) => {
    expect(() => normalizeIndicatorRuleEditInputs([input])).toThrow(message);
  });
  it('should clear the rule metadata patched with no value', () => {
    expect(normalizeIndicatorRuleEditInputs([
      { key: 'x_opencti_rule_status', value: [null] },
      { key: 'x_opencti_rule_logsource', value: [null] },
    ])).toEqual([
      { key: 'x_opencti_rule_status', value: [] },
      { key: 'x_opencti_rule_logsource', value: [] },
    ]);
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
