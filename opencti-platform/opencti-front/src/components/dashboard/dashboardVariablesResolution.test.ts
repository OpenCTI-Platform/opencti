import { describe, expect, it } from 'vitest';
import cases from '../../../../opencti-graphql/tests/data/dashboard-variables/resolution-cases.json';
import { buildDefaultVariableValues, isValidVariableValue, resolveVariablesInFilterGroup } from './dashboardVariablesResolution';
import type { DashboardVariable } from './dashboard-types';

describe('Dashboard variables resolution - shared cases', () => {
  it.each(cases.map((c) => [c.name, c] as const))('%s', (_, testCase) => {
    const input = structuredClone(testCase.input);
    const dateVariableIds = new Set<string>('dateVariableIds' in testCase ? testCase.dateVariableIds : []);
    // A case without time zone is computed in UTC, the default of the back: it is given explicitly here, so that the
    // expectations never depend on the time zone of the machine running the tests (the default of the front).
    const timeZone = 'timeZone' in testCase ? testCase.timeZone : 'UTC';
    const result = resolveVariablesInFilterGroup(input, new Map(Object.entries(testCase.values)), { dateVariableIds, timeZone });
    expect(result).toEqual(testCase.expected);
    expect(input).toEqual(testCase.input);
  });
});

describe('Dashboard variables resolution - frontend specifics', () => {
  it('should handle missing filter groups', () => {
    expect(resolveVariablesInFilterGroup(undefined, new Map())).toEqual({ filters: undefined, unresolved: [] });
  });
  it('should build values from defaults, skipping empty ones', () => {
    const variables = [
      { id: 'a', name: 'A', type: 'text', restriction: { mode: 'none' }, defaultValue: 'x' },
      { id: 'b', name: 'B', type: 'text', restriction: { mode: 'none' }, defaultValue: null },
      { id: 'c', name: 'C', type: 'text', restriction: { mode: 'none' }, defaultValue: '' },
    ] as DashboardVariable[];
    expect(buildDefaultVariableValues(variables)).toEqual(new Map([['a', 'x']]));
    expect(buildDefaultVariableValues(undefined)).toEqual(new Map());
  });
});

describe('isValidVariableValue', () => {
  const none = { mode: 'none' } as const;
  const base = { id: '11111111-1111-4111-8111-111111111111', name: 'V', restriction: none, defaultValue: null };
  const of = (type: DashboardVariable['type']) => ({ ...base, type }) as DashboardVariable;

  it('accepts only true or false for a boolean', () => {
    expect(isValidVariableValue(of('boolean'), 'true')).toBe(true);
    expect(isValidVariableValue(of('boolean'), 'false')).toBe(true);
    expect(isValidVariableValue(of('boolean'), 'banana')).toBe(false);
    expect(isValidVariableValue(of('boolean'), 'True')).toBe(false);
  });

  it('accepts only a finite number for a numeric', () => {
    expect(isValidVariableValue(of('numeric'), '42')).toBe(true);
    expect(isValidVariableValue(of('numeric'), '-1.5')).toBe(true);
    expect(isValidVariableValue(of('numeric'), 'abc')).toBe(false);
    expect(isValidVariableValue(of('numeric'), 'Infinity')).toBe(false);
    expect(isValidVariableValue(of('numeric'), '  ')).toBe(false);
  });

  it('accepts only a parseable date for a date', () => {
    expect(isValidVariableValue(of('date'), '2024-01-15T12:00:00.000Z')).toBe(true);
    expect(isValidVariableValue(of('date'), 'not a date')).toBe(false);
  });

  it.each([
    ['boolean', 'true'],
    ['numeric', '42'],
    ['date', '2024-01-15T12:00:00.000Z'],
  ] as const)('refuses a %s value with surrounding spaces, which would reach the filters as is', (type, value) => {
    expect(isValidVariableValue(of(type), value)).toBe(true);
    expect(isValidVariableValue(of(type), ` ${value}`)).toBe(false);
    expect(isValidVariableValue(of(type), `${value} `)).toBe(false);
    expect(isValidVariableValue(of(type), ` ${value} `)).toBe(false);
  });

  it.each(['text', 'entity', 'label', 'marking', 'user', 'group', 'status', 'killChainPhase', 'vocabulary', 'entityType'] as const)(
    'accepts any non-empty string without a variable token for %s',
    (type) => {
      expect(isValidVariableValue(of(type), 'Energy')).toBe(true);
      expect(isValidVariableValue(of(type), '')).toBe(false);
      expect(isValidVariableValue(of(type), '   ')).toBe(false);
      expect(isValidVariableValue(of(type), '$var:22222222-2222-4222-8222-222222222222')).toBe(false);
      expect(isValidVariableValue(of(type), 'a $var: b')).toBe(false);
    },
  );

  it('also requires the value to be in the pool of a selection restriction', () => {
    const selection = { ...of('text'), restriction: { mode: 'selection', values: ['FR', 'DE'] } } as DashboardVariable;
    expect(isValidVariableValue(selection, 'FR')).toBe(true);
    expect(isValidVariableValue(selection, 'US')).toBe(false);
    const numeric = { ...of('numeric'), restriction: { mode: 'selection', values: ['1', '2'] } } as DashboardVariable;
    expect(isValidVariableValue(numeric, '2')).toBe(true);
    expect(isValidVariableValue(numeric, '3')).toBe(false);
    expect(isValidVariableValue(numeric, 'abc')).toBe(false);
  });
});
