import { describe, expect, it, vi } from 'vitest';
import cases from '../../../data/dashboard-variables/resolution-cases.json';
import { logApp } from '../../../../src/config/conf';
import {
  buildDashboardDateVariableIds,
  buildDashboardVariableDefaultValues,
  computeDashboardVariablesUsage,
  containsDashboardVariableToken,
  extractDashboardVariableIds,
  isStrictIsoDate,
  isValidDashboardVariableValue,
  isValidTimeZone,
  parseDashboardVariableToken,
  resolveDashboardVariablesInWidgets,
  resolveVariablesInFilterGroup,
  toDashboardVariableToken,
} from '../../../../src/modules/dashboard/dashboard-variables-resolution';

const VAR_A = '11111111-1111-4111-8111-111111111111';
const VAR_B = '22222222-2222-4222-8222-222222222222';

describe('Dashboard variables resolution - shared cases', () => {
  it.each(cases.map((c) => [c.name, c] as const))('%s', (_, testCase) => {
    const input = structuredClone(testCase.input);
    const dateVariableIds = new Set<string>('dateVariableIds' in testCase ? testCase.dateVariableIds : []);
    // A case without time zone is computed in UTC, the default of the back, given explicitly like in the front tests.
    const timeZone = 'timeZone' in testCase ? testCase.timeZone : 'UTC';
    const result = resolveVariablesInFilterGroup(input, new Map(Object.entries(testCase.values)), { dateVariableIds, timeZone });
    expect(result).toEqual(testCase.expected);
    // the input is never mutated
    expect(input).toEqual(testCase.input);
  });
});

describe('Dashboard variables resolution - backend specifics', () => {
  it('should handle missing filter groups', () => {
    expect(resolveVariablesInFilterGroup(undefined, new Map())).toEqual({ filters: undefined, unresolved: [] });
    expect(resolveVariablesInFilterGroup(null, new Map())).toEqual({ filters: null, unresolved: [] });
  });
  it('should build and parse tokens', () => {
    expect(toDashboardVariableToken(VAR_A)).toEqual(`$var:${VAR_A}`);
    expect(parseDashboardVariableToken(`$var:${VAR_A}`)).toEqual(VAR_A);
    expect(parseDashboardVariableToken('$var:nope')).toBeNull();
    expect(parseDashboardVariableToken(42)).toBeNull();
  });
  it('should detect a token anywhere in a serialized string', () => {
    expect(containsDashboardVariableToken(JSON.stringify({ values: [`$var:${VAR_A}`] }))).toBe(true);
    expect(containsDashboardVariableToken(JSON.stringify({ values: ['$var:nope'] }))).toBe(false);
  });
  it('should extract every referenced variable id', () => {
    const filters = { mode: 'and', filters: [{ key: 'createdBy', values: [`$var:${VAR_A}`, `$var:${VAR_B}`] }], filterGroups: [] };
    expect(extractDashboardVariableIds(filters)).toEqual([VAR_A, VAR_B]);
  });
  it('should compute variable usage over filters, dynamicFrom and dynamicTo only', () => {
    const token = (id: string) => ({ mode: 'and', filters: [{ key: 'createdBy', values: [`$var:${id}`] }], filterGroups: [] });
    const usage = computeDashboardVariablesUsage({
      'widget-1': { dataSelection: [{ filters: token(VAR_A) }] },
      'widget-2': { dataSelection: [{ dynamicFrom: token(VAR_A), dynamicTo: token(VAR_B) }] },
      'widget-3': { dataSelection: [{ filters: undefined }] },
      'widget-4': {},
    });
    expect(usage.get(VAR_A)).toEqual(['widget-1', 'widget-2']);
    expect(usage.get(VAR_B)).toEqual(['widget-2']);
    expect(computeDashboardVariablesUsage(undefined).size).toEqual(0);
  });
});

describe('Dashboard variables resolution - publication', () => {
  const token = (id: string) => ({ mode: 'and', filters: [{ key: ['createdBy'], values: [`$var:${id}`] }], filterGroups: [] });

  it('should build default values, ignoring malformed or empty ones', () => {
    const values = buildDashboardVariableDefaultValues([
      { id: VAR_A, defaultValue: 'value-a' },
      { id: VAR_B, defaultValue: '' },
      { id: 42, defaultValue: 'x' },
      null,
    ]);
    expect(values).toEqual(new Map([[VAR_A, 'value-a']]));
    expect(buildDashboardVariableDefaultValues(undefined).size).toEqual(0);
    expect(buildDashboardVariableDefaultValues({ not: 'an array' }).size).toEqual(0);
  });

  it('should resolve filters, dynamicFrom and dynamicTo of every widget', () => {
    type TestWidget = { id: string; dataSelection?: { label: string; filters?: unknown; dynamicFrom?: unknown; dynamicTo?: unknown }[] };
    const widgets: Record<string, TestWidget> = {
      'widget-1': { id: 'widget-1', dataSelection: [{ label: 'a', filters: token(VAR_A), dynamicFrom: token(VAR_A), dynamicTo: token(VAR_A) }] },
      'widget-2': { id: 'widget-2', dataSelection: [{ label: 'b' }] },
      'widget-3': { id: 'widget-3' },
    };
    const { widgets: resolved, unresolved } = resolveDashboardVariablesInWidgets(widgets, new Map([[VAR_A, 'value-a']]));
    expect(unresolved).toEqual([]);
    const [selection] = resolved['widget-1'].dataSelection ?? [];
    expect([selection.filters, selection.dynamicFrom, selection.dynamicTo].map((group) => (group as { filters: { values: string[] }[] }).filters[0].values))
      .toEqual([['value-a'], ['value-a'], ['value-a']]);
    expect(resolved['widget-2']).toEqual(widgets['widget-2']);
    expect(resolved['widget-3']).toEqual(widgets['widget-3']);
    expect(JSON.stringify(widgets)).toContain('$var:');
  });

  it('should list the date variables, ignoring malformed ones', () => {
    const ids = buildDashboardDateVariableIds([
      { id: VAR_A, type: 'date' },
      { id: VAR_B, type: 'text' },
      { id: 42, type: 'date' },
      null,
    ]);
    expect(ids).toEqual(new Set([VAR_A]));
    expect(buildDashboardDateVariableIds(undefined).size).toEqual(0);
    expect(buildDashboardDateVariableIds({ not: 'an array' }).size).toEqual(0);
  });

  it('should shift a date variable by one UTC day for lte and gt only', () => {
    const dateFilter = (operator: string) => ({ mode: 'and', filters: [{ key: ['created_at'], values: [`$var:${VAR_A}`], operator }], filterGroups: [] });
    const widgets = {
      'widget-1': { dataSelection: [{ filters: dateFilter('lte'), dynamicFrom: dateFilter('gt'), dynamicTo: dateFilter('gte') }] },
    };
    const values = new Map([[VAR_A, '2024-01-15T00:00:00.000Z']]);
    const { widgets: resolved, unresolved } = resolveDashboardVariablesInWidgets(widgets, values, { dateVariableIds: new Set([VAR_A]) });
    expect(unresolved).toEqual([]);
    const [selection] = resolved['widget-1'].dataSelection ?? [];
    expect([selection.filters, selection.dynamicFrom, selection.dynamicTo].map((group) => (group as { filters: { values: string[] }[] }).filters[0].values))
      .toEqual([['2024-01-16T00:00:00.000Z'], ['2024-01-16T00:00:00.000Z'], ['2024-01-15T00:00:00.000Z']]);
    // Without the date variable ids, nothing is shifted.
    const [unshifted] = resolveDashboardVariablesInWidgets(widgets, values).widgets['widget-1'].dataSelection ?? [];
    expect((unshifted.filters as { filters: { values: string[] }[] }).filters[0].values).toEqual(['2024-01-15T00:00:00.000Z']);
  });

  it('should shift a date variable by one calendar day in the time zone given', () => {
    const lteFilter = { mode: 'and', filters: [{ key: ['created_at'], values: [`$var:${VAR_A}`], operator: 'lte' }], filterGroups: [] };
    const widgets = { 'widget-1': { dataSelection: [{ filters: lteFilter }] } };
    // Local midnight of 2026-03-29 in Paris, the day of the spring forward: the next local midnight is 23 hours later.
    const values = new Map([[VAR_A, '2026-03-28T23:00:00.000Z']]);
    const shiftedIn = (timeZone?: string) => {
      const [selection] = resolveDashboardVariablesInWidgets(widgets, values, { dateVariableIds: new Set([VAR_A]), timeZone }).widgets['widget-1'].dataSelection ?? [];
      return (selection.filters as { filters: { values: string[] }[] }).filters[0].values;
    };
    expect(shiftedIn('Europe/Paris')).toEqual(['2026-03-29T22:00:00.000Z']);
    // UTC by default.
    expect(shiftedIn()).toEqual(['2026-03-29T23:00:00.000Z']);
  });

  it('should report every variable left without value', () => {
    const { unresolved } = resolveDashboardVariablesInWidgets({
      'widget-1': { dataSelection: [{ filters: token(VAR_A) }] },
      'widget-2': { dataSelection: [{ filters: token(VAR_B) }, { filters: token(VAR_A) }] },
    }, new Map());
    expect(unresolved).toEqual([VAR_A, VAR_B]);
  });
});

describe('Dashboard variables resolution - defaults invalid for their type', () => {
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
  ])('should ignore the %s default "%s"', (type, defaultValue) => {
    expect(buildDashboardVariableDefaultValues([{ id: VAR_A, type, defaultValue }]).size).toEqual(0);
  });

  it.each([
    ['numeric', '42'],
    ['boolean', 'false'],
    ['date', '2026-01-01T00:00:00.000Z'],
    ['text', ' Energy sector '],
  ])('should keep the valid %s default "%s"', (type, defaultValue) => {
    expect(buildDashboardVariableDefaultValues([{ id: VAR_A, type, defaultValue }])).toEqual(new Map([[VAR_A, defaultValue]]));
  });

  it('should check the default of an untyped variable as a text', () => {
    expect(buildDashboardVariableDefaultValues([{ id: VAR_A, defaultValue: ' 42' }])).toEqual(new Map([[VAR_A, ' 42']]));
  });
});

describe('Dashboard variables resolution - strict ISO-8601 dates', () => {
  // Parsed by some engines only (V8, not Safari), local time in some engines and UTC in others, or not a calendar day.
  it.each(['2024/01/01', 'March 7 2024', '2024-01-01 10:00', '2024-01-01T10:00:00', '2024-13-01', '2024-02-30'])(
    'should refuse the date value "%s"',
    (value) => {
      expect(isStrictIsoDate(value)).toBe(false);
      expect(isValidDashboardVariableValue('date', value)).toBe(false);
      expect(buildDashboardVariableDefaultValues([{ id: VAR_A, type: 'date', defaultValue: value }]).size).toEqual(0);
    },
  );

  it.each(['2024-01-01', '2024-01-01T10:00:00Z', '2024-01-01T10:00:00.5+02:00'])('should accept the date value "%s"', (value) => {
    expect(isStrictIsoDate(value)).toBe(true);
    expect(isValidDashboardVariableValue('date', value)).toBe(true);
    expect(buildDashboardVariableDefaultValues([{ id: VAR_A, type: 'date', defaultValue: value }])).toEqual(new Map([[VAR_A, value]]));
  });
});

describe('Dashboard variables resolution - time zone validation', () => {
  it.each([
    ['Europe/Paris', true],
    ['UTC', true],
    ['Not/AZone', false],
    ['', false],
  ])('should tell whether "%s" is a valid time zone', (timeZone, expected) => {
    expect(isValidTimeZone(timeZone)).toBe(expected);
  });

  it('should still fall back to UTC for an invalid time zone, logging it once', () => {
    const warnSpy = vi.spyOn(logApp, 'warn');
    try {
      const lteFilter = { mode: 'and', filters: [{ key: ['created_at'], values: [`$var:${VAR_A}`], operator: 'lte' }], filterGroups: [] };
      const values = new Map([[VAR_A, '2026-03-28T23:00:00.000Z']]);
      const resolve = () => resolveVariablesInFilterGroup(lteFilter, values, { dateVariableIds: new Set([VAR_A]), timeZone: 'Invalid/LoggedOnce' });
      // One UTC day later, not the 23 hours of a calendar day in a zone springing forward that night.
      expect(resolve().filters.filters[0].values).toEqual(['2026-03-29T23:00:00.000Z']);
      expect(resolve().filters.filters[0].values).toEqual(['2026-03-29T23:00:00.000Z']);
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('time zone'), { timeZone: 'Invalid/LoggedOnce' });
    } finally {
      warnSpy.mockRestore();
    }
  });
});
