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
});
