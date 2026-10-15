import { describe, expect, it } from 'vitest';
import cases from '../../../data/dashboard-variables/resolution-cases.json';
import {
  buildDashboardDateVariableIds,
  buildDashboardVariableDefaultValues,
  computeDashboardVariablesUsage,
  containsDashboardVariableToken,
  extractDashboardVariableIds,
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
    // The date cases use January timestamps in UTC: one calendar day later is the same instant whether it is counted in
    // UTC (back) or in the local time zone (front), since no common time zone changes its daylight saving time then.
    const dateVariableIds = new Set<string>('dateVariableIds' in testCase ? testCase.dateVariableIds : []);
    const result = resolveVariablesInFilterGroup(input, new Map(Object.entries(testCase.values)), { dateVariableIds });
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

  it('should report every variable left without value', () => {
    const { unresolved } = resolveDashboardVariablesInWidgets({
      'widget-1': { dataSelection: [{ filters: token(VAR_A) }] },
      'widget-2': { dataSelection: [{ filters: token(VAR_B) }, { filters: token(VAR_A) }] },
    }, new Map());
    expect(unresolved).toEqual([VAR_A, VAR_B]);
  });
});
