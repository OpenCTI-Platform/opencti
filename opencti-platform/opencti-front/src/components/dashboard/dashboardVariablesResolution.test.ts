import { describe, expect, it } from 'vitest';
import cases from '../../../../opencti-graphql/tests/data/dashboard-variables/resolution-cases.json';
import { buildDefaultVariableValues, resolveVariablesInFilterGroup } from './dashboardVariablesResolution';
import type { DashboardVariable } from './dashboard-types';

describe('Dashboard variables resolution - shared cases', () => {
  it.each(cases.map((c) => [c.name, c] as const))('%s', (_, testCase) => {
    const input = structuredClone(testCase.input);
    const result = resolveVariablesInFilterGroup(input, new Map(Object.entries(testCase.values)));
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
