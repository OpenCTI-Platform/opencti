import React, { ReactNode } from 'react';
import { describe, expect, it } from 'vitest';
import { renderHook } from '@testing-library/react';
import { DashboardVariablesProvider, useDashboardVariableDefinitions, useOptionalDashboardVariableDefinitions } from './DashboardVariablesContext';
import type { DashboardVariable } from './dashboard-types';

const LABEL_VARIABLE: DashboardVariable = {
  id: '11111111-1111-4111-8111-111111111111',
  name: 'Label',
  type: 'label',
  restriction: { mode: 'none' },
  defaultValue: null,
};

const wrapWith = (variables: DashboardVariable[] | undefined) => {
  const Wrapper = ({ children }: { children: ReactNode }) => (
    <DashboardVariablesProvider variables={variables}>{children}</DashboardVariablesProvider>
  );
  return Wrapper;
};

describe('DashboardVariablesContext', () => {
  it('exposes no variable and no dashboard scope without provider', () => {
    expect(renderHook(() => useDashboardVariableDefinitions()).result.current).toEqual([]);
    expect(renderHook(() => useOptionalDashboardVariableDefinitions()).result.current).toBeUndefined();
  });

  it('exposes the provided definitions', () => {
    const wrapper = wrapWith([LABEL_VARIABLE]);
    expect(renderHook(() => useDashboardVariableDefinitions(), { wrapper }).result.current).toEqual([LABEL_VARIABLE]);
    expect(renderHook(() => useOptionalDashboardVariableDefinitions(), { wrapper }).result.current).toEqual([LABEL_VARIABLE]);
  });

  it('keeps the dashboard scope with an empty list, so a token of a deleted variable is still recognized', () => {
    const wrapper = wrapWith([]);
    expect(renderHook(() => useOptionalDashboardVariableDefinitions(), { wrapper }).result.current).toEqual([]);
  });

  it('behaves as no provider when given no variables (feature off, home dashboard)', () => {
    const wrapper = wrapWith(undefined);
    expect(renderHook(() => useDashboardVariableDefinitions(), { wrapper }).result.current).toEqual([]);
    expect(renderHook(() => useOptionalDashboardVariableDefinitions(), { wrapper }).result.current).toBeUndefined();
  });
});
