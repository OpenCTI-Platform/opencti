import { describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import type { DashboardVariable } from './dashboard-types';
import { useDashboardDefaultVariableValues } from './DashboardVariableValuesContext';

let enabledFlags: string[] = [];
vi.mock('../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (flag: string) => enabledFlags.includes(flag) }),
}));

const variables = [
  { id: 'v1', name: 'Sector', type: 'text', restriction: { mode: 'none' }, defaultValue: 'energy' },
] as DashboardVariable[];

describe('useDashboardDefaultVariableValues', () => {
  it('provides the default values when the feature flag is enabled', () => {
    enabledFlags = ['DASHBOARD_VARIABLES'];
    const { result } = renderHook(() => useDashboardDefaultVariableValues(variables));
    expect(result.current).toEqual(new Map([['v1', 'energy']]));
  });

  it('provides no value when the feature flag is disabled', () => {
    enabledFlags = [];
    const { result } = renderHook(() => useDashboardDefaultVariableValues(variables));
    expect(result.current.size).toEqual(0);
  });
  it('keeps the same values while the variables content does not change', () => {
    enabledFlags = ['DASHBOARD_VARIABLES'];
    const { result, rerender } = renderHook(({ list }) => useDashboardDefaultVariableValues(list), { initialProps: { list: variables } });
    const first = result.current;
    // A manifest save gives a new array with the same content: widgets must not all re-resolve
    rerender({ list: variables.map((v) => ({ ...v })) });
    expect(result.current).toBe(first);
    rerender({ list: [{ ...variables[0], defaultValue: 'finance' }] as DashboardVariable[] });
    expect(result.current).not.toBe(first);
    expect(result.current.get('v1')).toEqual('finance');
  });
});
