import { describe, expect, it, vi } from 'vitest';
import { addDays } from 'date-fns';
import cases from '../../../../opencti-graphql/tests/data/dashboard-variables/resolution-cases.json';
import { buildDefaultVariableValues, isStrictIsoDate, isValidVariableValue, resolveVariablesInFilterGroup } from './dashboardVariablesResolution';
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

  it('accepts only a strict ISO-8601 date for a date', () => {
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

describe('buildDefaultVariableValues - defaults invalid for their type', () => {
  const variableOf = (type: DashboardVariable['type'], defaultValue: string | null, restriction: unknown = { mode: 'none' }) => (
    { id: 'v', name: 'V', type, restriction, defaultValue } as DashboardVariable
  );

  it.each([
    ['numeric', ' 42'],
    ['numeric', '42 '],
    ['numeric', 'abc'],
    ['boolean', ' true'],
    ['boolean', 'maybe'],
    ['date', ' 2026-01-01T00:00:00.000Z'],
    ['date', 'not a date'],
    ['text', '$var:22222222-2222-4222-8222-222222222222'],
    ['text', '   '],
  ] as const)('ignores the %s default "%s"', (type, defaultValue) => {
    expect(buildDefaultVariableValues([variableOf(type, defaultValue)])).toEqual(new Map());
  });

  it.each([
    ['numeric', '42'],
    ['boolean', 'false'],
    ['date', '2026-01-01T00:00:00.000Z'],
    ['text', ' Energy sector '],
  ] as const)('keeps the valid %s default "%s"', (type, defaultValue) => {
    expect(buildDefaultVariableValues([variableOf(type, defaultValue)])).toEqual(new Map([['v', defaultValue]]));
  });

  it('does not check the selection pool, which is checked when the variable is written', () => {
    const selection = { mode: 'selection', values: ['FR'] };
    expect(buildDefaultVariableValues([variableOf('text', 'DE', selection)])).toEqual(new Map([['v', 'DE']]));
  });
});

describe('Dashboard variables resolution - strict ISO-8601 dates', () => {
  const dateVariable = (defaultValue: string | null = null) => (
    { id: 'v', name: 'V', type: 'date', restriction: { mode: 'none' }, defaultValue } as DashboardVariable
  );

  // Parsed by some engines only (V8, not Safari), local time in some engines and UTC in others, or not a calendar day.
  it.each(['2024/01/01', 'March 7 2024', '2024-01-01 10:00', '2024-01-01T10:00:00', '2024-13-01', '2024-02-30'])(
    'refuses the date value "%s"',
    (value) => {
      expect(isStrictIsoDate(value)).toBe(false);
      expect(isValidVariableValue(dateVariable(), value)).toBe(false);
      expect(buildDefaultVariableValues([dateVariable(value)])).toEqual(new Map());
    },
  );

  it.each(['2024-01-01', '2024-01-01T10:00:00Z', '2024-01-01T10:00:00.5+02:00'])('accepts the date value "%s"', (value) => {
    expect(isStrictIsoDate(value)).toBe(true);
    expect(isValidVariableValue(dateVariable(), value)).toBe(true);
    expect(buildDefaultVariableValues([dateVariable(value)])).toEqual(new Map([['v', value]]));
  });
});

describe('Dashboard variables resolution - unusable time zone', () => {
  const variableId = '44444444-4444-4444-8444-444444444444';
  const lteFilter = { mode: 'and', filters: [{ key: 'created_at', values: [`$var:${variableId}`], operator: 'lte', mode: 'or' }], filterGroups: [] };
  const shift = (value: string, timeZone: string) => {
    const options = { dateVariableIds: new Set([variableId]), timeZone };
    return resolveVariablesInFilterGroup(lteFilter, new Map([[variableId, value]]), options).filters.filters[0].values;
  };

  // Each case uses its own zone: a zone is reported once per page load.
  it.each(['Nowhere/Unknown', 'Etc/Unknown'])('shifts by one local calendar day, like the fixed date input, in "%s", warning once', (timeZone) => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const iso = '2026-03-28T23:00:00.000Z';
      // Computed like the fixed date input, so that the expectation holds in the time zone of any machine.
      const expected = addDays(new Date(iso), 1).toISOString();
      expect(shift(iso, timeZone)).toEqual([expected]);
      expect(shift(iso, timeZone)).toEqual([expected]);
      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls[0][0]).toContain(timeZone);
    } finally {
      warn.mockRestore();
    }
  });

  it('returns a value that is not a date unchanged', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      expect(shift('not a date', 'Nowhere/Else')).toEqual(['not a date']);
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });
});
