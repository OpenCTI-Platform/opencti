import { describe, expect, it } from 'vitest';
import { getInvalidDefaultVariableIds } from './dashboardVariableDefaults';
import type { DashboardVariable } from './dashboard-types';

const variable = (id: string, type: 'text' | 'numeric' | 'boolean' | 'date', defaultValue: string | null): DashboardVariable => ({
  id,
  name: id,
  type,
  restriction: { mode: 'none' },
  defaultValue,
});

describe('getInvalidDefaultVariableIds', () => {
  it('lists a numeric default with surrounding spaces, which the default values ignore', () => {
    expect(getInvalidDefaultVariableIds([variable('n', 'numeric', ' 42')])).toEqual(new Set(['n']));
  });

  it('lists a boolean default with surrounding spaces', () => {
    expect(getInvalidDefaultVariableIds([variable('b', 'boolean', ' true')])).toEqual(new Set(['b']));
  });

  it('lists a default that is not a number for a numeric variable', () => {
    expect(getInvalidDefaultVariableIds([variable('n', 'numeric', 'abc')])).toEqual(new Set(['n']));
  });

  it('does not list valid defaults', () => {
    const variables = [
      variable('n', 'numeric', '42'),
      variable('b', 'boolean', 'false'),
      variable('t', 'text', 'Energy'),
    ];
    expect(getInvalidDefaultVariableIds(variables).size).toBe(0);
  });

  it('does not list a variable without default, it is just unset', () => {
    expect(getInvalidDefaultVariableIds([variable('n', 'numeric', null), variable('t', 'text', '')]).size).toBe(0);
  });

  it('does not list a text default with spaces inside or around', () => {
    expect(getInvalidDefaultVariableIds([variable('t1', 'text', 'Energy sector'), variable('t2', 'text', ' Energy ')]).size).toBe(0);
  });

  it('lists only the invalid ones among several variables', () => {
    const variables = [
      variable('ok', 'numeric', '1'),
      variable('ko', 'numeric', '1 '),
      variable('none', 'boolean', null),
    ];
    expect(getInvalidDefaultVariableIds(variables)).toEqual(new Set(['ko']));
  });

  it('returns an empty set for no variable', () => {
    expect(getInvalidDefaultVariableIds([]).size).toBe(0);
  });
});
